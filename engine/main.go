package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// checkNames is the set of selectable scan checks (also used to validate
// the --checks flag). "all" enables every check.
var checkNames = map[string]bool{
	"bola":                true,
	"mass-assignment":     true,
	"bfla":                true,
	"exposure":            true,
	"missing-auth":        true,
	"security-misconfig":  true,
	"rate-limit":          true,
	"debug-endpoints":     true,
}

func parseChecks(s string) (map[string]bool, error) {
	result := map[string]bool{}
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		for k := range checkNames {
			result[k] = true
		}
		return result, nil
	}
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if !checkNames[p] {
			return nil, fmt.Errorf("unknown check %q (valid: bola, mass-assignment, bfla, exposure, missing-auth, security-misconfig, rate-limit, debug-endpoints)", p)
		}
		result[p] = true
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no valid checks selected")
	}
	return result, nil
}

func main() {
	base := flag.String("base", "", "target API base URL (required)")
	outJSON := flag.String("out-json", "findings.json", "path to write findings.json")
	outHTML := flag.String("out-html", "report.html", "path to write report.html")
	checksFlag := flag.String("checks", "all", "comma-separated checks to run (bola,mass-assignment,bfla,exposure,missing-auth) or 'all'")
	flag.Parse()

	if *base == "" {
		fmt.Fprintln(os.Stderr, "error: --base is required")
		os.Exit(2)
	}

	checks, err := parseChecks(*checksFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if err := runWithChecks(*base, *outJSON, *outHTML, checks); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
