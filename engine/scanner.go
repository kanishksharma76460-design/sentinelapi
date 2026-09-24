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

func allChecks() map[string]bool {
	m := map[string]bool{}
	for k := range checkNames {
		m[k] = true
	}
	return m
}

func run(base, outJSON, outHTML string) error {
	return runWithChecks(base, outJSON, outHTML, allChecks())
}

func runWithChecks(base, outJSON, outHTML string, checks map[string]bool) error {
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
		if checks["bola"] {
			findings = append(findings, checkBola(client, base, ep, userA, userB, aToken, seenBola)...)
		}
		if checks["mass-assignment"] {
			findings = append(findings, checkMassAssignment(client, base, ep, aToken)...)
		}
		if checks["bfla"] {
			findings = append(findings, checkBFLA(client, base, ep, aToken)...)
		}

		_, hasSchema := schemaPaths(ep.Op)
		if hasSchema || opHasSecurity(ep.Op) {
			// baseline = a 200 response for A's own resource (or direct call)
			filled, body := resolveBaseline(client, base, ep, userA, aToken)
			if checks["exposure"] && hasSchema && filled != "" && body != nil {
				findings = append(findings, checkExposure(ep, body, base, filled, aToken)...)
			}
			if checks["missing-auth"] && opHasSecurity(ep.Op) && filled != "" {
				findings = append(findings, checkMissingAuth(client, ep, base, filled)...)
			}
		}
	}

	// API-wide checks (run once per scan, not per endpoint).
	if checks["security-misconfig"] {
		findings = append(findings, checkSecurityMisconfig(client, base)...)
	}
	if checks["rate-limit"] {
		findings = append(findings, checkRateLimit(client, base)...)
	}
	if checks["debug-endpoints"] {
		findings = append(findings, checkDebugEndpoints(client, base)...)
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

// checkSecurityMisconfig flags version disclosure in response headers and
// missing hardening headers (OWASP API7/API8 — Security Misconfiguration).
func checkSecurityMisconfig(client *http.Client, base string) []finding {
	resp, err := client.Get(base + "/")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var leaks []string
	for _, h := range []string{"X-Powered-By", "X-AspNet-Version", "X-Runtime",
		"X-Generator", "X-Runtime-Platform"} {
		if v := resp.Header.Get(h); v != "" {
			leaks = append(leaks, h+": "+v)
		}
	}
	if sv := resp.Header.Get("Server"); sv != "" && !strings.EqualFold(sv, "uvicorn") {
		leaks = append(leaks, "Server: "+sv)
	}

	var missing []string
	if resp.Header.Get("X-Content-Type-Options") == "" {
		missing = append(missing, "X-Content-Type-Options")
	}
	if resp.Header.Get("X-Frame-Options") == "" &&
		resp.Header.Get("Content-Security-Policy") == "" {
		missing = append(missing, "X-Frame-Options")
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security")
	}

	if len(leaks) == 0 && len(missing) == 0 {
		return nil
	}
	detail := ""
	if len(leaks) > 0 {
		detail += "Leaks server software/version in response headers: " +
			strings.Join(leaks, ", ") + ". "
	}
	if len(missing) > 0 {
		detail += "Missing hardening headers: " + strings.Join(missing, ", ") + "."
	}
	return []finding{{
		Severity:     "LOW",
		Title:        "Security Misconfiguration",
		Endpoint:     "ALL",
		Detail:       detail,
		Reproduction: fmt.Sprintf("curl -sI %s/", base),
		Evidence: []map[string]interface{}{{
			"headers_leaked":  leaks,
			"headers_missing": missing,
		}},
	}}
}

// checkRateLimit floods a cheap endpoint and flags the absence of any 429 /
// Retry-After response (OWASP API4 — Unrestricted Resource Consumption).
func checkRateLimit(client *http.Client, base string) []finding {
	const n = 15
	for i := 0; i < n; i++ {
		resp, err := client.Get(base + "/health")
		if err != nil {
			continue
		}
		limited := resp.StatusCode == http.StatusTooManyRequests ||
			resp.Header.Get("Retry-After") != ""
		resp.Body.Close()
		if limited {
			return nil
		}
	}
	return []finding{{
		Severity: "MEDIUM",
		Title:    "Missing Rate Limiting",
		Endpoint: "ALL",
		Detail: fmt.Sprintf(
			"Sent %d rapid requests with no 429/Retry-After response — the API has no rate limiting (OWASP API4: Unrestricted Resource Consumption).",
			n),
		Reproduction: fmt.Sprintf(
			"for i in $(seq 1 %d); do curl -s -o /dev/null -w '%%{http_code}\\n' %s/health; done",
			n, base),
		Evidence: []map[string]interface{}{{
			"requests_sent": n, "rate_limited": false,
		}},
	}}
}

// debugPaths are common debug/staging/inventory endpoints that should never be
// reachable in production.
var debugPaths = []string{
	"/debug", "/debug/pprof", "/metrics", "/actuator", "/actuator/health",
	"/console", "/phpinfo.php", "/.env", "/.git/config", "/admin/debug",
}

// checkDebugEndpoints probes for exposed debug/inventory endpoints that leak
// internal information (OWASP API8 — Security Misconfiguration / API9 — Improper
// Inventory Management).
func checkDebugEndpoints(client *http.Client, base string) []finding {
	var out []finding
	for _, p := range debugPaths {
		resp, err := client.Get(base + p)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		lower := strings.ToLower(string(body))
		if strings.Contains(lower, "debug") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "config") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "version") || strings.Contains(lower, "env") {
			out = append(out, finding{
				Severity: "HIGH",
				Title:    "Exposed Debug Endpoint",
				Endpoint: "GET " + p,
				Detail: fmt.Sprintf(
					"Debug/inventory endpoint %s is publicly reachable and returns internal information.",
					p),
				Reproduction: fmt.Sprintf("curl -s %s%s", base, p),
				Evidence: []map[string]interface{}{{
					"path": p, "http_status": resp.StatusCode,
				}},
			})
		}
	}
	return out
}
