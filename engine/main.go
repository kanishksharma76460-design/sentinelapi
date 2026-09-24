package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	base := flag.String("base", "", "target API base URL (required)")
	outJSON := flag.String("out-json", "findings.json", "path to write findings.json")
	outHTML := flag.String("out-html", "report.html", "path to write report.html")
	flag.Parse()

	if *base == "" {
		fmt.Fprintln(os.Stderr, "error: --base is required")
		os.Exit(2)
	}

	if err := run(*base, *outJSON, *outHTML); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
