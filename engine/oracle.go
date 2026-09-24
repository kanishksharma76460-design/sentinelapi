package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// identifierFields are the fields returned by /register that identify a
// principal. Order matters: it is the substitution and detection order.
var identifierFields = []string{"id", "username", "email", "order_id", "post_id"}

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

func markersFromUser(u map[string]interface{}) []marker {
	var out []marker
	for _, k := range identifierFields {
		if v, ok := u[k]; ok {
			out = append(out, marker{Key: k, Raw: v, Str: stringify(v)})
		}
	}
	return out
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

// declaredKeys returns the property names declared in the 200 response schema,
// or ok=false if no schema is declared.
func declaredKeys(op map[string]interface{}) (map[string]bool, bool) {
	v, ok := dig(op, "responses", "200", "content", "application/json", "schema", "properties")
	if !ok {
		return nil, false
	}
	props, ok := v.(map[string]interface{})
	if !ok {
		return nil, false
	}
	keys := make(map[string]bool, len(props))
	for k := range props {
		keys[k] = true
	}
	return keys, true
}
