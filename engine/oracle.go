package main

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// sensitiveHints name patterns whose presence in a response is a plausible leak.
var sensitiveHints = []string{
	"password", "passwd", "secret", "token", "ssn", "card", "cvv",
	"pan", "key", "otp", "aadhaar", "pan_number",
}

// marker is one identifying field of a principal, with its raw and string form.
type marker struct {
	Key string
	Raw interface{}
	Str string
}

// markersFromUser infers a principal's identifying fields generically from the
// registration response (any scalar field), instead of hardcoding field names —
// so the scanner works against any API with a register endpoint.
func markersFromUser(u map[string]interface{}) []marker {
	keys := make([]string, 0, len(u))
	for k := range u {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []marker
	for _, k := range keys {
		if v, ok := u[k]; ok && isScalar(v) {
			out = append(out, marker{Key: k, Raw: v, Str: stringify(v)})
		}
	}
	return out
}

func isScalar(v interface{}) bool {
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		return false
	}
	return true
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case json.Number:
		return t.String()
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// repr mirrors Python's repr for marker values in the human-readable detail.
func repr(v interface{}) string {
	switch t := v.(type) {
	case json.Number:
		return t.String()
	case string:
		return "'" + t + "'"
	case bool:
		return strconv.FormatBool(t)
	default:
		return stringify(v)
	}
}

// containsValue reports whether target appears anywhere in the JSON object.
// Values are compared by their canonical string form so that int (Go marker)
// and json.Number (decoded response) compare equal.
func containsValue(obj interface{}, target string) bool {
	switch t := obj.(type) {
	case map[string]interface{}:
		for _, v := range t {
			if containsValue(v, target) {
				return true
			}
		}
	case []interface{}:
		for _, v := range t {
			if containsValue(v, target) {
				return true
			}
		}
	case json.Number:
		return t.String() == target
	case string:
		return t == target
	case bool:
		return strconv.FormatBool(t) == target
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64) == target
	}
	return false
}

func sensitive(key string) bool {
	k := strings.ToLower(key)
	for _, h := range sensitiveHints {
		if strings.Contains(k, h) {
			return true
		}
	}
	return false
}

func dig(m map[string]interface{}, keys ...string) (interface{}, bool) {
	var cur interface{} = m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = mm[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// opHasSecurity reports whether the operation DECLARES a security requirement
// (a non-empty OpenAPI "security" array).
func opHasSecurity(op map[string]interface{}) bool {
	if op == nil {
		return false
	}
	sec, ok := op["security"].([]interface{})
	return ok && len(sec) > 0
}

// schemaPaths returns the set of dotted paths declared in the 200 response
// schema, or ok=false if no schema is declared.
func schemaPaths(op map[string]interface{}) (map[string]bool, bool) {
	v, ok := dig(op, "responses", "200", "content", "application/json", "schema", "properties")
	if !ok {
		return nil, false
	}
	props, ok := v.(map[string]interface{})
	if !ok {
		return nil, false
	}
	var out []string
	collectSchemaPaths(props, "", &out)
	set := make(map[string]bool, len(out))
	for _, p := range out {
		set[p] = true
	}
	return set, true
}

// collectSchemaPaths walks a declared "properties" map and emits dotted paths.
func collectSchemaPaths(props map[string]interface{}, prefix string, out *[]string) {
	for name, raw := range props {
		p := name
		if prefix != "" {
			p = prefix + "." + name
		}
		ps, ok := raw.(map[string]interface{})
		if !ok {
			*out = append(*out, p)
			continue
		}
		if sub, ok := ps["properties"].(map[string]interface{}); ok {
			collectSchemaPaths(sub, p, out)
		} else if items, ok := ps["items"].(map[string]interface{}); ok {
			if sub, ok := items["properties"].(map[string]interface{}); ok {
				collectSchemaPaths(sub, p, out)
			} else {
				*out = append(*out, p)
			}
		} else {
			*out = append(*out, p)
		}
	}
}

// collectResponsePaths walks a JSON response and emits dotted paths to leaves.
func collectResponsePaths(obj interface{}, prefix string, out *[]string) {
	switch t := obj.(type) {
	case map[string]interface{}:
		for k, v := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if isContainer(v) {
				collectResponsePaths(v, p, out)
			} else {
				*out = append(*out, p)
			}
		}
	case []interface{}:
		for _, v := range t {
			collectResponsePaths(v, prefix, out)
		}
	}
}

func isContainer(v interface{}) bool {
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		return true
	}
	return false
}

func lastSegment(p string) string {
	if i := strings.LastIndex(p, "."); i >= 0 {
		return p[i+1:]
	}
	return p
}

// hasKey reports whether `key` appears as an object key anywhere in the JSON.
func hasKey(obj interface{}, key string) bool {
	switch t := obj.(type) {
	case map[string]interface{}:
		if _, ok := t[key]; ok {
			return true
		}
		for _, v := range t {
			if hasKey(v, key) {
				return true
			}
		}
	case []interface{}:
		for _, v := range t {
			if hasKey(v, key) {
				return true
			}
		}
	}
	return false
}
