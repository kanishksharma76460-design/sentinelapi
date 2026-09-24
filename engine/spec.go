package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var paramRe = regexp.MustCompile(`\{([^}]+)\}`)

// endpoint is a single operation (any HTTP method).
type endpoint struct {
	Method string
	Path   string
	Op     map[string]interface{}
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true,
	"delete": true, "head": true, "options": true, "trace": true,
}

func fetchJSON(client *http.Client, url string) (map[string]interface{}, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	var v map[string]interface{}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func fetchSpec(client *http.Client, base string) (map[string]interface{}, error) {
	return fetchJSON(client, base+"/openapi.json")
}

// allEndpoints returns every operation (any method, any path) in the spec.
func allEndpoints(spec map[string]interface{}) []endpoint {
	var out []endpoint
	paths, _ := spec["paths"].(map[string]interface{})
	for path, v := range paths {
		methods, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		for method, vv := range methods {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			op, _ := vv.(map[string]interface{})
			out = append(out, endpoint{Method: strings.ToUpper(method), Path: path, Op: op})
		}
	}
	return out
}

// pathParams returns the names inside {braces} in a path.
func pathParams(path string) []string {
	var out []string
	for _, m := range paramRe.FindAllStringSubmatch(path, -1) {
		out = append(out, m[1])
	}
	return out
}
