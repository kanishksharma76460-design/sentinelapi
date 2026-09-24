package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ---------------------------------------------------------------------------
// New detection checks (JWT, SQLi/NoSQLi, CORS, SSRF, GraphQL, spec audit).
// All stdlib-only, no external dependencies.
// ---------------------------------------------------------------------------

// ---- shared helpers --------------------------------------------------------

func b64url(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func b64urlDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func getBody(client *http.Client, u string) (int, string, error) {
	resp, err := client.Get(u)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), nil
}

func getWithOrigin(client *http.Client, u, origin string) (int, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Origin", origin)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, nil
}

func basePort(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// ---- JWT analysis ----------------------------------------------------------

func b64Segment(s string) bool {
	if s == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// isJWT reports whether s looks like a compact JWS (three dot-joined segments).
func isJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	return b64Segment(parts[0]) && b64Segment(parts[1]) && b64Segment(parts[2])
}

func parseJWT(token string) (map[string]interface{}, map[string]interface{}, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	hb, err1 := b64urlDecode(parts[0])
	pb, err2 := b64urlDecode(parts[1])
	if err1 != nil || err2 != nil {
		return nil, nil, false
	}
	var h, p map[string]interface{}
	if json.Unmarshal(hb, &h) != nil || json.Unmarshal(pb, &p) != nil {
		return nil, nil, false
	}
	return h, p, true
}

func findJWTInJSON(v interface{}, out *[]string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for _, val := range t {
			findJWTInJSON(val, out)
		}
	case []interface{}:
		for _, val := range t {
			findJWTInJSON(val, out)
		}
	case string:
		if isJWT(t) {
			*out = append(*out, t)
		}
	}
}

func signJWT(header, payload map[string]interface{}, secret string) string {
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h := b64url(hb)
	p := b64url(pb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + b64url(mac.Sum(nil))
}

func noneJWT(payload map[string]interface{}) string {
	hb, _ := json.Marshal(map[string]interface{}{"alg": "none", "typ": "JWT"})
	pb, _ := json.Marshal(payload)
	return b64url(hb) + "." + b64url(pb) + "."
}

var jwtCommonSecrets = []string{
	"secret", "password", "changeme", "key", "jwt_secret", "supersecret",
	"123456", "admin", "default", "token", "thisisasecret",
}

// jwtLoginTargets are candidate credential endpoints, tried with common creds.
var jwtLoginTargets = []struct{ method, path string }{
	{http.MethodPost, "/login"},
	{http.MethodPost, "/auth/login"},
	{http.MethodPost, "/api/login"},
	{http.MethodPost, "/auth/token"},
	{http.MethodPost, "/token"},
}

// jwtProtectedProbes are endpoints that verify a bearer token, used to test
// whether a forged token is accepted.
var jwtProtectedProbes = []string{"/me", "/users/me", "/profile", "/api/me"}

func checkJWT(client *http.Client, base string) []finding {
	// 1. Harvest a JWT from login endpoints or /register.
	var tokens []string
	for _, t := range jwtLoginTargets {
		for _, creds := range []string{
			`{"username":"alice","password":"password"}`,
			`{"username":"admin","password":"admin"}`,
			`{"username":"test","password":"test"}`,
		} {
			resp, err := client.Post(base+t.path, "application/json", strings.NewReader(creds))
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				var v interface{}
				if json.Unmarshal(b, &v) == nil {
					findJWTInJSON(v, &tokens)
				}
			}
		}
	}
	if len(tokens) == 0 {
		return nil
	}

	header, payload, ok := parseJWT(tokens[0])
	if !ok {
		return nil
	}

	// accepts reports whether a forged token is accepted by a protected probe.
	accepts := func(token string) string {
		for _, p := range jwtProtectedProbes {
			req, _ := http.NewRequest(http.MethodGet, base+p, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return p
			}
		}
		return ""
	}

	var out []finding

	// 2. alg:none — signature stripped, no verification.
	if ep := accepts(noneJWT(payload)); ep != "" {
		out = append(out, finding{
			Severity: "CRITICAL",
			Title:    "JWT Signature Not Verified (alg:none)",
			Endpoint: "GET " + ep,
			Detail: fmt.Sprintf(
				"A JWT with header {\"alg\":\"none\"} and no signature is accepted by %s. The server trusts the token header without verifying a signature — attackers can forge any identity.",
				ep),
			Reproduction: fmt.Sprintf(
				`printf '{"alg":"none","typ":"JWT"}' | base64 | tr -d '='; # paste payload, then: curl -s -H 'Authorization: Bearer <forged>' '%s%s'`,
				base, ep),
			Evidence: []map[string]interface{}{{"alg": "none", "accepted_by": ep}},
		})
	}

	// 3. Weak HMAC secret — re-sign with common secrets and test acceptance.
	for _, secret := range jwtCommonSecrets {
		forged := signJWT(header, payload, secret)
		if ep := accepts(forged); ep != "" {
			out = append(out, finding{
				Severity: "HIGH",
				Title:    "Weak JWT Signing Secret",
				Endpoint: "GET " + ep,
				Detail: fmt.Sprintf(
					"A JWT re-signed with the guessable HMAC secret %q is accepted by %s. The signing key is weak/known — tokens can be forged.",
					secret, ep),
				Reproduction: fmt.Sprintf(
					`echo -n '<header>.<payload>' | openssl dgst -sha256 -hmac '%s' -binary | base64 | tr '+/' '-_' | tr -d '='; # then curl -s -H 'Authorization: Bearer <forged>' '%s%s'`,
					secret, base, ep),
				Evidence: []map[string]interface{}{{"secret": secret, "accepted_by": ep}},
			})
			break
		}
	}

	// 4. Missing expiry.
	if _, hasExp := payload["exp"]; !hasExp {
		out = append(out, finding{
			Severity: "LOW",
			Title:    "JWT Has No Expiry",
			Endpoint: "ALL",
			Detail:    "Issued JWT payloads contain no 'exp' claim — tokens never expire and remain valid indefinitely if leaked.",
			Reproduction: fmt.Sprintf(
				"curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"password\"}' %s/login",
				base),
			Evidence: []map[string]interface{}{{"missing_claim": "exp"}},
		})
	}

	return out
}

// ---- SQL / NoSQL injection -------------------------------------------------

var sqlErrorSignatures = []string{
	"you have an error in your sql", "sql syntax", "unclosed quotation",
	"mysql", "sqlite", "postgres", "psql", "odbc", "oledb", "pymongo",
	"bson", "operationalerror", "programmingerror", "syntax error near",
	"unterminated string", "invalid input syntax",
}

func sqlInjectionTargets(base string, endpoints []endpoint) []string {
	// Prefer spec endpoints with query params; fall back to common paths.
	var targets []string
	seen := map[string]bool{}
	for _, ep := range endpoints {
		if ep.Method != http.MethodGet {
			continue
		}
		p := ep.Path
		if strings.Contains(p, "{") {
			// substitute a placeholder so we can append a query string
			p = paramRe.ReplaceAllString(p, "1")
		}
		u := base + p + "?q="
		if !seen[u] {
			seen[u] = true
			targets = append(targets, u)
		}
	}
	if len(targets) == 0 {
		for _, p := range []string{"/search", "/users", "/items", "/posts", "/products", "/lookup"} {
			targets = append(targets, base+p+"?q=")
		}
	}
	return targets
}

func checkSQLi(client *http.Client, base string, endpoints []endpoint) []finding {
	var out []finding
	seen := map[string]bool{}

	for _, target := range sqlInjectionTargets(base, endpoints) {
		// error-based SQLi
		for _, payload := range []string{"'", `"`, "1' OR '1'='1", "') OR ('1'='1"} {
			status, body, err := getBody(client, target+url.QueryEscape(payload))
			if err != nil {
				continue
			}
			lower := strings.ToLower(body)
			for _, sig := range sqlErrorSignatures {
				if strings.Contains(lower, sig) {
					key := "sqli:" + target
					if seen[key] {
						break
					}
					seen[key] = true
					out = append(out, finding{
						Severity: "HIGH",
						Title:    "SQL Injection",
						Endpoint: "GET " + strings.TrimPrefix(target, base),
						Detail: fmt.Sprintf(
							"Injecting %q into a query parameter returns a SQL error (%q). The input is concatenated into a query unsanitized.",
							payload, sig),
						Reproduction: fmt.Sprintf("curl -s '%s%s'", target, url.QueryEscape(payload)),
						Evidence: []map[string]interface{}{{
							"payload": payload, "signature": sig, "http_status": status,
						}},
					})
					break
				}
			}
			if status == http.StatusInternalServerError && strings.Contains(lower, "error") {
				key := "sqli:" + target
				if !seen[key] {
					seen[key] = true
					out = append(out, finding{
						Severity: "MEDIUM",
						Title:    "Possible SQL/NoSQL Injection (error response)",
						Endpoint: "GET " + strings.TrimPrefix(target, base),
						Detail: fmt.Sprintf(
							"Injecting %q returns HTTP 500 with an error body — the input appears to be parsed as a query.",
							payload),
						Reproduction: fmt.Sprintf("curl -s '%s%s'", target, url.QueryEscape(payload)),
						Evidence: []map[string]interface{}{{
							"payload": payload, "http_status": status,
						}},
					})
				}
			}
		}

		// NoSQL operator injection — flag only when the operator returns more
		// data than a benign baseline query (prevents false positives on
		// endpoints that simply ignore the query parameter).
		benignStatus, benignBody, err := getBody(client, target+url.QueryEscape("__sentinel_nomatch__"))
		if err == nil && benignStatus == http.StatusOK {
			for _, payload := range []string{`{"$ne":null}`, `{"$gt":""}`} {
				status, body, err := getBody(client, target+url.QueryEscape(payload))
				if err != nil {
					continue
				}
				key := "nosqli:" + target
				if status == http.StatusOK && body != benignBody &&
					strings.Contains(strings.ToLower(body), "user") && !seen[key] {
					seen[key] = true
					out = append(out, finding{
						Severity: "HIGH",
						Title:    "NoSQL Injection",
						Endpoint: "GET " + strings.TrimPrefix(target, base),
						Detail: fmt.Sprintf(
							"Injecting the NoSQL operator %q returns records where a benign query returns none — the query parameter is passed to a document database unsanitized.",
							payload),
						Reproduction: fmt.Sprintf("curl -s '%s%s'", target, url.QueryEscape(payload)),
						Evidence: []map[string]interface{}{{"payload": payload}},
					})
					break
				}
			}
		}
	}
	return out
}

// ---- CORS misconfiguration -------------------------------------------------

func checkCORS(client *http.Client, base string, endpoints []endpoint) []finding {
	// Probe the root plus each GET path once, with an attacker origin.
	probes := []string{base + "/"}
	for _, ep := range endpoints {
		if ep.Method != http.MethodGet || strings.Contains(ep.Path, "{") {
			continue
		}
		probes = append(probes, base+ep.Path)
	}
	seen := map[string]bool{}
	var out []finding
	for _, u := range probes {
		status, hdr, err := getWithOrigin(client, u, "https://attacker.example")
		if err != nil {
			continue
		}
		acao := hdr.Get("Access-Control-Allow-Origin")
		if acao == "" {
			continue
		}
		acac := strings.EqualFold(hdr.Get("Access-Control-Allow-Credentials"), "true")
		reflected := acao == "https://attacker.example" || acao == "null"
		switch {
		case reflected && acac:
			if seen["high"] {
				continue
			}
			seen["high"] = true
			out = append(out, finding{
				Severity: "HIGH",
				Title:    "CORS Misconfiguration (credentialed reflection)",
				Endpoint: "GET " + strings.TrimPrefix(u, base),
				Detail: fmt.Sprintf(
					"The API reflects an attacker-supplied Origin (%q) with Access-Control-Allow-Credentials: true (status %d). A malicious site can read authenticated responses.",
					acao, status),
				Reproduction: fmt.Sprintf(
					"curl -s -H 'Origin: https://attacker.example' -D - -o /dev/null '%s'",
					u),
				Evidence: []map[string]interface{}{{
					"origin": "https://attacker.example", "allow_origin": acao,
					"allow_credentials": true,
				}},
			})
		case acao == "*" && acac:
			if seen["high"] {
				continue
			}
			seen["high"] = true
			out = append(out, finding{
				Severity: "HIGH",
				Title:    "CORS Misconfiguration (wildcard + credentials)",
				Endpoint: "GET " + strings.TrimPrefix(u, base),
				Detail:    "The API sends Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true — an invalid combination that browsers reject but signals a broken CORS policy.",
				Reproduction: fmt.Sprintf("curl -s -H 'Origin: https://attacker.example' -D - -o /dev/null '%s'", u),
				Evidence: []map[string]interface{}{{
					"allow_origin": "*", "allow_credentials": true,
				}},
			})
		case reflected && !acac:
			if seen["low"] {
				continue
			}
			seen["low"] = true
			out = append(out, finding{
				Severity: "LOW",
				Title:    "CORS Reflects Arbitrary Origin",
				Endpoint: "GET " + strings.TrimPrefix(u, base),
				Detail: fmt.Sprintf(
					"The API reflects arbitrary Origins (%q) in Access-Control-Allow-Origin without credentials — safer, but the allow-list is effectively open.",
					acao),
				Reproduction: fmt.Sprintf("curl -s -H 'Origin: https://attacker.example' -D - -o /dev/null '%s'", u),
				Evidence: []map[string]interface{}{{
					"origin": "https://attacker.example", "allow_origin": acao,
				}},
			})
		}
	}
	return out
}

// ---- SSRF in the target ----------------------------------------------------

var urlParamNames = []string{"url", "target", "uri", "redirect", "callback",
	"next", "fetch", "proxy", "webhook", "dest", "link", "endpoint", "host"}

func ssrfTargets(base string, endpoints []endpoint) []string {
	var out []string
	seen := map[string]bool{}
	for _, ep := range endpoints {
		if ep.Method != http.MethodGet || !strings.Contains(ep.Path, "?") {
			continue
		}
		for _, p := range urlParamNames {
			u := base + ep.Path + "?" + p + "="
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	if len(out) == 0 {
		for _, p := range []string{"/fetch", "/proxy", "/redirect", "/webhook", "/url"} {
			out = append(out, base+p+"?url=")
		}
	}
	return out
}

func checkSSRF(client *http.Client, base string, endpoints []endpoint) []finding {
	port := basePort(base)
	// Baseline: the target's own internal health body.
	_, healthBody, err := getBody(client, base+"/health")
	if err != nil || strings.TrimSpace(healthBody) == "" {
		return nil
	}
	hb := strings.TrimSpace(healthBody)

	// Try several internal addresses (external port, common app ports, metadata).
	internalCandidates := []string{
		fmt.Sprintf("http://127.0.0.1:%s/health", port),
		"http://127.0.0.1:8000/health",
		"http://localhost:8000/health",
		"http://127.0.0.1:8080/health",
		"http://127.0.0.1:80/health",
		"http://169.254.169.254/latest/meta-data/",
	}
	seenC := map[string]bool{}
	var cands []string
	for _, c := range internalCandidates {
		if !seenC[c] {
			seenC[c] = true
			cands = append(cands, c)
		}
	}

	var out []finding
	seen := map[string]bool{}
	for _, target := range ssrfTargets(base, endpoints) {
		for _, internal := range cands {
			status, body, err := getBody(client, target+url.QueryEscape(internal))
			if err != nil {
				continue
			}
			lower := strings.ToLower(body)
			meta := strings.Contains(lower, "ami-id") ||
				strings.Contains(lower, "instance-id") ||
				strings.Contains(lower, "instance-type")
			if (hb != "" && strings.Contains(body, hb)) || meta {
				key := "ssrf:" + target
				if seen[key] {
					break
				}
				seen[key] = true
				out = append(out, finding{
					Severity: "HIGH",
					Title:    "Server-Side Request Forgery (SSRF)",
					Endpoint: "GET " + strings.TrimPrefix(target, base),
					Detail: fmt.Sprintf(
						"Supplying %q to a URL parameter caused the server to fetch an internal address and return its content. Attackers can reach internal services / cloud metadata.",
						internal),
					Reproduction: fmt.Sprintf("curl -s '%s%s'", target, url.QueryEscape(internal)),
					Evidence: []map[string]interface{}{{
						"internal_url": internal, "http_status": status,
					}},
				})
				break
			}
		}
	}
	return out
}

// ---- GraphQL ---------------------------------------------------------------

const graphqlIntrospection = `{"query":"{ __schema { queryType { name } types { name } } }"}`

func checkGraphQL(client *http.Client, base string) []finding {
	var out []finding
	for _, path := range []string{"/graphql", "/api/graphql", "/gql"} {
		resp, err := client.Post(base+path, "application/json", strings.NewReader(graphqlIntrospection))
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		lower := strings.ToLower(string(b))
		if !strings.Contains(lower, "__schema") {
			continue
		}
		out = append(out, finding{
			Severity: "MEDIUM",
			Title:    "GraphQL Introspection Enabled",
			Endpoint: "POST " + path,
			Detail: fmt.Sprintf(
				"GraphQL endpoint %s answers introspection queries — the full schema (types, fields) is exposed to unauthenticated callers.",
				path),
			Reproduction: fmt.Sprintf("curl -s -X POST -H 'Content-Type: application/json' -d '%s' %s%s", graphqlIntrospection, base, path),
			Evidence: []map[string]interface{}{{
				"path": path, "introspection": true,
			}},
		})
		break
	}
	return out
}

// ---- OpenAPI spec audit ----------------------------------------------------

var undocumentedWordlist = []string{
	"/api", "/api/v1", "/api/v2", "/v1", "/v2", "/admin", "/internal",
	"/swagger", "/docs", "/redoc", "/healthz", "/readyz", "/version",
	"/.env", "/backup", "/export",
}

func checkSpecAudit(spec map[string]interface{}, client *http.Client, base string) []finding {
	var out []finding

	if spec != nil {
		declared := map[string]bool{}
		for _, ep := range allEndpoints(spec) {
			declared[strings.ToLower(ep.Method)+" "+ep.Path] = true
		}
		// a. securitySchemes declared?
		if _, ok := dig(spec, "components", "securitySchemes"); !ok {
			out = append(out, finding{
				Severity: "LOW",
				Title:    "OpenAPI Declares No Security Schemes",
				Endpoint: "ALL",
				Detail:    "The OpenAPI spec defines no components.securitySchemes — no authentication mechanism is documented for the API.",
				Reproduction: fmt.Sprintf("curl -s %s/openapi.json", base),
				Evidence: []map[string]interface{}{{"missing": "components.securitySchemes"}},
			})
		}
		// b. undocumented endpoints: live paths that answer but are not in spec
		seen := map[string]bool{}
		for _, p := range undocumentedWordlist {
			status, _, err := getBody(client, base+p)
			if err != nil || status == http.StatusNotFound {
				continue
			}
			// rough match: consider it undocumented if no spec path matches its prefix
			key := "undoc:" + p
			if seen[key] {
				continue
			}
			seen[key] = true
			matched := false
			for k := range declared {
				if strings.HasPrefix(strings.ToLower(k), "get "+p) {
					matched = true
					break
				}
			}
			if matched {
				continue
			}
			out = append(out, finding{
				Severity: "MEDIUM",
				Title:    "Undocumented Endpoint",
				Endpoint: "GET " + p,
				Detail: fmt.Sprintf(
					"Path %s answers with HTTP %d but is not declared in the OpenAPI spec — an unmanaged attack surface.",
					p, status),
				Reproduction: fmt.Sprintf("curl -s -i %s%s", base, p),
				Evidence: []map[string]interface{}{{
					"path": p, "http_status": status,
				}},
			})
			if len(seen) >= 5 {
				break
			}
		}
	} else {
		// No spec available — still probe for undocumented inventory.
		for _, p := range undocumentedWordlist {
			status, _, err := getBody(client, base+p)
			if err != nil || status == http.StatusNotFound {
				continue
			}
			out = append(out, finding{
				Severity: "LOW",
				Title:    "Reachable Path Outside Known Spec",
				Endpoint: "GET " + p,
				Detail: fmt.Sprintf(
					"Path %s answers with HTTP %d while no OpenAPI spec could be fetched — inventory is unverified.",
					p, status),
				Reproduction: fmt.Sprintf("curl -s -i %s%s", base, p),
				Evidence: []map[string]interface{}{{
					"path": p, "http_status": status,
				}},
			})
		}
	}
	return out
}
