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
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
  :root {
    --bg0: #02040a; --bg1: #090c15;
    --panel: rgba(15, 20, 35, 0.6);
    --border: rgba(255, 255, 255, 0.08);
    --text: #f0f4f8; --muted: #94a3b8;
    --cyan: #00f0ff; --violet: #b026ff; --green: #10b981;
  }
  body { margin:0; font-family:'Outfit', system-ui, -apple-system, sans-serif;
         background: linear-gradient(135deg, var(--bg0), var(--bg1)); color:var(--text); min-height:100vh;
         background-attachment:fixed; }
  header { padding:40px 48px; border-bottom:1px solid var(--border);
           background:rgba(2, 4, 10, 0.5); backdrop-filter:blur(10px);
           position:sticky; top:0; z-index:10; }
  h1 { margin:0 0 10px; font-size:28px; font-weight:800;
       background:linear-gradient(110deg,#00f0ff,#b026ff); -webkit-background-clip:text; color:transparent; }
  .sub { color:var(--muted); font-size:15px; font-weight:300; }
  .stats { margin-top:16px; font-size:15px; color:var(--cyan); font-weight:500; letter-spacing:0.05em; }
  main { padding:40px 48px; display:grid; gap:24px; max-width:1200px; margin:0 auto; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:16px; padding:24px;
          backdrop-filter:blur(16px); transition:all 0.3s;
          box-shadow: 0 10px 30px rgba(0,0,0,0.5), inset 0 1px 1px rgba(255,255,255,0.05); }
  .card:hover { transform:translateY(-4px); border-color:rgba(255,255,255,0.2); box-shadow: 0 15px 40px rgba(0,0,0,0.6); }
  .card-head { display:flex; align-items:center; gap:12px; margin-bottom:12px; }
  .badge { font-size:11px; font-weight:800; letter-spacing:0.1em; text-transform:uppercase; color:#fff;
           padding:5px 12px; border-radius:999px; text-shadow:0 1px 2px rgba(0,0,0,0.3); }
  .title { font-weight:700; font-size:17px; }
  .endpoint { display:inline-block; background:rgba(0,0,0,0.3); color:var(--cyan); border:1px solid rgba(0,240,255,0.2);
              font-family:'JetBrains Mono', monospace; font-size:14px; padding:6px 10px; border-radius:8px; margin-bottom:12px; }
  .detail { color:#cbd5e1; font-size:15px; line-height:1.6; margin:0 0 16px; font-weight:300; }
  .curl { background:rgba(0,0,0,0.5); border:1px solid var(--border); border-radius:12px;
          padding:14px 16px; font-family:'JetBrains Mono', monospace; font-size:13px; color:var(--green); overflow-x:auto; }
  details { color:var(--muted); font-size:13px; margin-top:16px; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; }
  summary { cursor:pointer; }
  details pre { background:rgba(0,0,0,0.5); padding:14px; border-radius:12px; overflow-x:auto; margin-top:10px; font-family:'JetBrains Mono', monospace; color:#94a3b8; text-transform:none; border:1px solid var(--border); }
  .empty { color:var(--muted); padding:60px; text-align:center; font-size:20px; }
</style>
</head>
<body>
<header>
  <h1>SentinelAPI — Scan Report</h1>
  <div class="sub">Target: ` + html.EscapeString(title) + ` · ` + html.EscapeString(base) + `</div>
  <div class="stats">` + html.EscapeString(sum) + `</div>
</header>
<main>
  ` + strings.Join(cards, "\n") + `
</main>
</body>
</html>`
}


