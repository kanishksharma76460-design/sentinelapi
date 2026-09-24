package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// finding is the shared contract with the Python scanner: the exact JSON keys
// the dashboard consumes.
type finding struct {
	Severity     string                   `json:"severity"`
	Title        string                   `json:"title"`
	Endpoint     string                   `json:"endpoint"`
	Detail       string                   `json:"detail"`
	Reproduction string                   `json:"reproduction"`
	Evidence     []map[string]interface{} `json:"evidence"`
}

var severityOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func run(base, outJSON, outHTML string) error {
	client := &http.Client{Timeout: 10e9} // 10s
	base = strings.TrimRight(base, "/")

	spec, err := fetchSpec(client, base)
	if err != nil {
		return err
	}
	userA, err := registerUser(client, base, "alice")
	if err != nil {
		return err
	}
	userB, err := registerUser(client, base, "bob")
	if err != nil {
		return err
	}
	fmt.Printf("[*] registered alice (id=%v) and bob (id=%v)\n", userA["id"], userB["id"])

	endpoints := allEndpoints(spec)
	// deterministic order for reproducible output
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path == endpoints[j].Path {
			return endpoints[i].Method < endpoints[j].Method
		}
		return endpoints[i].Path < endpoints[j].Path
	})
	fmt.Printf("[*] found %d operation(s)\n", len(endpoints))

	aToken, _ := userA["token"].(string)

	var findings []finding
	seenBola := map[string]bool{}
	for _, ep := range endpoints {
		findings = append(findings, checkBola(client, base, ep, userA, userB, aToken, seenBola)...)
		findings = append(findings, checkMassAssignment(client, base, ep, aToken)...)
		findings = append(findings, checkBFLA(client, base, ep, aToken)...)

		_, hasSchema := schemaPaths(ep.Op)
		if hasSchema || opHasSecurity(ep.Op) {
			// baseline = a 200 response for A's own resource (or direct call)
			filled, body := resolveBaseline(client, base, ep, userA, aToken)
			if hasSchema && filled != "" && body != nil {
				findings = append(findings, checkExposure(ep, body, base, filled, aToken)...)
			}
			if opHasSecurity(ep.Op) && filled != "" {
				findings = append(findings, checkMissingAuth(client, ep, base, filled)...)
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})

	if err := writeFindings(outJSON, findings); err != nil {
		return err
	}
	if err := writeReport(outHTML, spec, findings, base); err != nil {
		return err
	}

	fmt.Printf("[*] %d finding(s):\n", len(findings))
	for _, f := range findings {
		fmt.Printf("    %-9s %s  ->  %s\n", f.Severity, f.Title, f.Endpoint)
	}
	fmt.Printf("[*] wrote %s\n", outJSON)
	fmt.Printf("[*] wrote %s\n", outHTML)
	return nil
}

func registerUser(client *http.Client, base, username string) (map[string]interface{}, error) {
	payload, _ := json.Marshal(map[string]string{"username": username})
	resp, err := client.Post(base+"/register", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register returned %d", resp.StatusCode)
	}
	var v map[string]interface{}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// doRequest performs a request of any method. Write methods get a minimal JSON
// body. An empty token means no Authorization header is sent.
func doRequest(client *http.Client, method, url, token string) (int, interface{}, error) {
	var body io.Reader
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		body = bytes.NewReader([]byte("{}"))
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		parsed = nil
	}
	return resp.StatusCode, parsed, nil
}

// resolveBaseline finds a 200 response for A's own resource (substituting A's
// identifiers into a single path param) or, for paths with no params, a direct
// call. Returns the filled path and the response body, or ""/nil if none.
func resolveBaseline(client *http.Client, base string, ep endpoint, a map[string]interface{}, aToken string) (string, interface{}) {
	params := pathParams(ep.Path)
	if len(params) == 1 {
		for _, m := range markersFromUser(a) {
			cand := strings.Replace(ep.Path, "{"+params[0]+"}", m.Str, 1)
			status, body, err := doRequest(client, ep.Method, base+cand, aToken)
			if err == nil && status == http.StatusOK {
				return cand, body
			}
		}
		return "", nil
	}
	// no path params: only read endpoints get a baseline (avoid mutating writes)
	if ep.Method != http.MethodGet && ep.Method != http.MethodHead {
		return "", nil
	}
	status, body, err := doRequest(client, ep.Method, base+ep.Path, aToken)
	if err == nil && status == http.StatusOK {
		return ep.Path, body
	}
	return "", nil
}

// checkBola is the cross-principal differential test (any HTTP method): substitute
// B's identifier into the path while presenting A's token, and flag if B-owned
// data comes back.
func checkBola(client *http.Client, base string, ep endpoint, a, b map[string]interface{}, aToken string, seen map[string]bool) []finding {
	params := pathParams(ep.Path)
	if len(params) != 1 {
		return nil
	}
	key := ep.Method + " " + ep.Path
	bMarkers := markersFromUser(b)
	var out []finding
	for _, sub := range bMarkers {
		filled := strings.Replace(ep.Path, "{"+params[0]+"}", sub.Str, 1)
		status, body, err := doRequest(client, ep.Method, base+filled, aToken)
		if err != nil || status != http.StatusOK {
			continue
		}
		for _, m := range bMarkers {
			if containsValue(body, m.Str) {
				if seen[key] {
					break
				}
				seen[key] = true
				out = append(out, finding{
					Severity: "CRITICAL",
					Title:    "Broken Object-Level Authorization (BOLA / IDOR)",
					Endpoint: key,
					Detail: fmt.Sprintf(
						"Account '%s' (token A) called %s and received data owned by '%s' (field %s=%s). No ownership check is enforced.",
						str(a["username"]), filled, str(b["username"]), m.Key, repr(m.Raw)),
					Reproduction: curlRepro(ep.Method, base, filled, aToken),
					Evidence:     []map[string]interface{}{{m.Key: m.Raw}},
				})
				break
			}
		}
	}
	return out
}

// checkExposure recursively diffs the actual response paths against the declared
// schema paths, flagging undeclared fields (including nested ones).
func checkExposure(ep endpoint, body interface{}, base, filled, aToken string) []finding {
	declared, ok := schemaPaths(ep.Op)
	if !ok {
		return nil
	}

	var respPaths []string
	collectResponsePaths(body, "", &respPaths)
	actual := make(map[string]bool, len(respPaths))
	for _, p := range respPaths {
		actual[p] = true
	}

	var extras []string
	for p := range actual {
		if !declared[p] {
			extras = append(extras, p)
		}
	}
	sort.Strings(extras)

	var out []finding
	for _, p := range extras {
		sev := "MEDIUM"
		if sensitive(lastSegment(p)) {
			sev = "HIGH"
		}
		out = append(out, finding{
			Severity: sev,
			Title:    "Excessive Data Exposure",
			Endpoint: ep.Method + " " + ep.Path,
			Detail: fmt.Sprintf(
				"Field '%s' is returned in the response but is NOT declared in the OpenAPI response schema. The client receives more data than the contract specifies.",
				p),
			Reproduction: curlRepro(ep.Method, base, filled, aToken),
			Evidence: []map[string]interface{}{{
				"undeclared_field": p,
				"declared_fields":  sortedKeys(declared),
			}},
		})
	}
	return out
}

// checkMissingAuth flags endpoints that DECLARE a security requirement in the
// spec but return data (HTTP 200) with no Authorization header at all.
func checkMissingAuth(client *http.Client, ep endpoint, base, filled string) []finding {
	status, body, err := doRequest(client, ep.Method, base+filled, "")
	if err != nil || status != http.StatusOK {
		return nil
	}
	if body == nil {
		return nil
	}
	return []finding{{
		Severity: "HIGH",
		Title:    "Broken Authentication",
		Endpoint: ep.Method + " " + ep.Path,
		Detail: fmt.Sprintf(
			"The spec declares an API-key security requirement for %s, but it returns data with no Authorization header (HTTP 200).",
			ep.Method+" "+ep.Path),
		Reproduction: curlNoAuth(ep.Method, base, filled),
		Evidence:     []map[string]interface{}{{"http_status": 200}},
	}}
}

// checkMassAssignment injects privileged fields into write endpoints and flags
// any that accept and reflect them.
func checkMassAssignment(client *http.Client, base string, ep endpoint, aToken string) []finding {
	switch ep.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return nil
	}
	const injected = `{"username":"mallory","role":"admin","is_admin":true,"balance":999999}`
	req, err := http.NewRequest(ep.Method, base+ep.Path, bytes.NewReader([]byte(injected)))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if aToken != "" {
		req.Header.Set("Authorization", "Bearer "+aToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil
	}
	data, _ := io.ReadAll(resp.Body)
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}
	var echoed []string
	for _, f := range []string{"role", "is_admin"} {
		if hasKey(parsed, f) {
			echoed = append(echoed, f)
		}
	}
	if len(echoed) == 0 {
		return nil
	}
	return []finding{{
		Severity: "HIGH",
		Title:    "Mass Assignment",
		Endpoint: ep.Method + " " + ep.Path,
		Detail: fmt.Sprintf(
			"The write endpoint accepts and persists privileged fields not part of its contract (%s). A client can escalate its own privileges.",
			strings.Join(echoed, ", ")),
		Reproduction: curlBody(ep.Method, base, ep.Path, aToken, injected),
		Evidence:     []map[string]interface{}{{"injected_fields": echoed}},
	}}
}

// checkBFLA flags admin-prefixed endpoints that a regular (non-admin) token can
// access — broken function-level authorization.
func checkBFLA(client *http.Client, base string, ep endpoint, aToken string) []finding {
	if !strings.HasPrefix(ep.Path, "/admin/") {
		return nil
	}
	status, _, err := doRequest(client, ep.Method, base+ep.Path, aToken)
	if err != nil || status != http.StatusOK {
		return nil
	}
	return []finding{{
		Severity: "HIGH",
		Title:    "Broken Function Level Authorization",
		Endpoint: ep.Method + " " + ep.Path,
		Detail: fmt.Sprintf(
			"A regular (non-admin) token can access %s (HTTP 200); the endpoint should be restricted to admin roles.",
			ep.Method+" "+ep.Path),
		Reproduction: curlRepro(ep.Method, base, ep.Path, aToken),
		Evidence:     []map[string]interface{}{{"role": "user", "http_status": 200}},
	}}
}

func curlRepro(method, base, path, token string) string {
	return fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' '%s%s'", token, base, path)
}

func curlNoAuth(method, base, path string) string {
	return fmt.Sprintf("curl -s -X %s '%s%s'", method, base, path)
}

func curlBody(method, base, path, token, body string) string {
	return fmt.Sprintf("curl -s -X %s -H 'Authorization: Bearer %s' -H 'Content-Type: application/json' -d '%s' '%s%s'",
		method, token, body, base, path)
}

func str(v interface{}) string {
	s, _ := v.(string)
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
