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

	endpoints := getParamEndpoints(spec)
	// deterministic order for reproducible output
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].Path < endpoints[j].Path })
	fmt.Printf("[*] found %d GET endpoint(s) with path parameters\n", len(endpoints))

	aToken, _ := userA["token"].(string)

	var findings []finding
	seen := map[string]bool{}
	for _, ep := range endpoints {
		findings = append(findings, checkBola(client, base, ep, userA, userB, aToken, seen)...)
		findings = append(findings, checkExposure(client, base, ep, userA, aToken)...)
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

func doGet(client *http.Client, url, token string) (int, interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var body interface{}
	if err := json.Unmarshal(data, &body); err != nil {
		body = nil
	}
	return resp.StatusCode, body, nil
}

// checkBola is the cross-principal differential test: substitute B's identifier
// into the path while presenting A's token, and flag if B-owned data comes back.
func checkBola(client *http.Client, base string, ep endpoint, a, b map[string]interface{}, aToken string, seen map[string]bool) []finding {
	params := pathParams(ep.Path)
	if len(params) != 1 {
		return nil
	}
	bMarkers := markersFromUser(b)
	var out []finding
	for _, sub := range bMarkers {
		filled := strings.Replace(ep.Path, "{"+params[0]+"}", sub.Str, 1)
		status, body, err := doGet(client, base+filled, aToken)
		if err != nil || status != http.StatusOK {
			continue
		}
		for _, m := range bMarkers {
			if containsValue(body, m.Str) {
				if seen[ep.Path] {
					break
				}
				seen[ep.Path] = true
				out = append(out, finding{
					Severity: "CRITICAL",
					Title:    "Broken Object-Level Authorization (BOLA / IDOR)",
					Endpoint: ep.Method + " " + ep.Path,
					Detail: fmt.Sprintf(
						"Account '%s' (token A) fetched %s and received data owned by '%s' (field %s=%s). No ownership check is enforced.",
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

// checkExposure diffs the actual response keys against the declared schema keys.
func checkExposure(client *http.Client, base string, ep endpoint, a map[string]interface{}, aToken string) []finding {
	params := pathParams(ep.Path)
	if len(params) != 1 {
		return nil
	}
	declared, ok := declaredKeys(ep.Op)
	if !ok {
		return nil
	}

	aMarkers := markersFromUser(a)
	var body interface{}
	var filled string
	for _, m := range aMarkers {
		cand := strings.Replace(ep.Path, "{"+params[0]+"}", m.Str, 1)
		status, b, err := doGet(client, base+cand, aToken)
		if err != nil {
			continue
		}
		if status == http.StatusOK {
			body = b
			filled = cand
			break
		}
	}
	if body == nil || filled == "" {
		return nil
	}

	obj, ok := body.(map[string]interface{})
	if !ok {
		return nil
	}
	actual := make(map[string]bool, len(obj))
	for k := range obj {
		actual[k] = true
	}

	var extras []string
	for k := range actual {
		if !declared[k] {
			extras = append(extras, k)
		}
	}
	sort.Strings(extras)

	var out []finding
	for _, k := range extras {
		sev := "MEDIUM"
		if sensitive(k) {
			sev = "HIGH"
		}
		out = append(out, finding{
			Severity: sev,
			Title:    "Excessive Data Exposure",
			Endpoint: ep.Method + " " + ep.Path,
			Detail: fmt.Sprintf(
				"Field '%s' is returned in the response but is NOT declared in the OpenAPI response schema. The client receives more data than the contract specifies.",
				k),
			Reproduction: curlRepro(ep.Method, base, filled, aToken),
			Evidence: []map[string]interface{}{{
				"undeclared_field": k,
				"declared_fields":  sortedKeys(declared),
			}},
		})
	}
	return out
}

func curlRepro(method, base, path, token string) string {
	return fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' '%s%s'", token, base, path)
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
