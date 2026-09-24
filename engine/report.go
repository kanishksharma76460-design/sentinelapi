package main

import (
	"encoding/json"
	"html"
	"os"
	"strconv"
	"strings"
)

func writeFindings(path string, findings []finding) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func writeReport(path string, spec map[string]interface{}, findings []finding, base string) error {
	return os.WriteFile(path, []byte(renderHTML(spec, findings, base)), 0o644)
}

var badgeColors = map[string]string{
	"CRITICAL": "#e5484d",
	"HIGH":     "#f76b15",
	"MEDIUM":   "#ffb224",
	"LOW":      "#3e63dd",
}

func renderHTML(spec map[string]interface{}, findings []finding, base string) string {
	title := "Target API"
	if info, ok := spec["info"].(map[string]interface{}); ok {
		if t, ok := info["title"].(string); ok {
			title = t
		}
	}

	var cards []string
	for _, f := range findings {
		badge := badgeColors[f.Severity]
		if badge == "" {
			badge = "#8d8d8d"
		}
		ev, _ := json.MarshalIndent(f.Evidence, "", "  ")
		var b strings.Builder
		b.WriteString(`<div class="card">`)
		b.WriteString(`<div class="card-head">`)
		b.WriteString(`<span class="badge" style="background:` + badge + `">` + html.EscapeString(f.Severity) + `</span>`)
		b.WriteString(`<span class="title">` + html.EscapeString(f.Title) + `</span>`)
		b.WriteString(`</div>`)
		b.WriteString(`<div class="endpoint">` + html.EscapeString(f.Endpoint) + `</div>`)
		b.WriteString(`<p class="detail">` + html.EscapeString(f.Detail) + `</p>`)
		b.WriteString(`<pre class="curl">` + html.EscapeString(f.Reproduction) + `</pre>`)
		b.WriteString(`<details><summary>evidence</summary><pre>` + html.EscapeString(string(ev)) + `</pre></details>`)
		b.WriteString(`</div>`)
		cards = append(cards, b.String())
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var summary []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if n, ok := counts[sev]; ok {
			summary = append(summary, sev+": "+strconv.Itoa(n))
		}
	}
	sum := strings.Join(summary, " · ")
	if sum == "" {
		sum = "no findings"
	}

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SentinelAPI — Scan Report</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         background:#0d1117; color:#e6edf3; }
  header { padding:28px 36px; border-bottom:1px solid #21262d;
           background:linear-gradient(180deg,#161b22,#0d1117); }
  h1 { margin:0 0 6px; font-size:22px; }
  .sub { color:#8b949e; font-size:13px; }
  .stats { margin-top:12px; font-size:14px; color:#79c0ff; }
  main { padding:24px 36px; display:grid; gap:16px; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px; }
  .card-head { display:flex; align-items:center; gap:10px; }
  .badge { font-size:11px; font-weight:700; letter-spacing:.04em; color:#fff;
           padding:3px 9px; border-radius:999px; }
  .title { font-weight:600; font-size:15px; }
  .endpoint { color:#79c0ff; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
              font-size:13px; margin:8px 0; }
  .detail { color:#c9d1d9; font-size:13px; line-height:1.5; margin:8px 0; }
  .curl { background:#0d1117; border:1px solid #30363d; border-radius:6px;
          padding:10px; font-size:12px; color:#7ee787; overflow-x:auto; }
  details { color:#8b949e; font-size:12px; margin-top:8px; }
  details pre { background:#0d1117; padding:8px; border-radius:6px; overflow-x:auto; }
  .empty { color:#8b949e; padding:40px; text-align:center; }
</style>
</head>
<body>
<header>
  <h1>🛡️ SentinelAPI — Scan Report</h1>
  <div class="sub">Target: ` + html.EscapeString(title) + ` · ` + html.EscapeString(base) + `</div>
  <div class="stats">` + html.EscapeString(sum) + `</div>
</header>
<main>
  ` + strings.Join(cards, "\n") + `
</main>
</body>
</html>`
}


