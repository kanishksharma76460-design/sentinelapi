const CHECKS = [
  ['BOLA / IDOR', 'Access other users\u2019 objects (broken object-level authorization).'],
  ['Mass Assignment', 'Privileged fields (role, is_admin) accepted on write endpoints.'],
  ['BFLA', 'Broken function-level authorization — admin endpoints open to any user.'],
  ['Data Exposure', 'Responses leak fields beyond the declared schema.'],
  ['Broken Auth', 'Endpoints that declare auth but serve data without a token.'],
  ['Misconfiguration', 'Server/version header leaks + missing hardening headers.'],
  ['Rate Limit', 'No 429 / Retry-After under rapid requests.'],
  ['Debug Endpoints', 'Exposed debug / inventory endpoints leaking internals.'],
  ['JWT Analysis', 'alg:none bypass, weak HMAC secret, missing expiry.'],
  ['SQL / NoSQLi', 'Error-based SQL injection + NoSQL operator ($ne) bypass.'],
  ['CORS', 'Credentialed origin reflection and wildcard misconfiguration.'],
  ['SSRF', 'Server-side fetch of internal / loopback / metadata addresses.'],
  ['GraphQL', 'Introspection enabled, exposing the full schema.'],
  ['Spec Audit', 'Undocumented endpoints + missing security schemes in OpenAPI.'],
]

export default function Guide({ onClose }) {
  return (
    <div className="guide-overlay" onClick={onClose}>
      <div className="guide-card bracket" onClick={e => e.stopPropagation()}>
        <div className="guide-head">
          <span className="guide-title">OPERATOR MANUAL</span>
          <button className="guide-close" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className="guide-body">
          <section>
            <h3>What it does</h3>
            <p>
              <b>Athera Secure</b> is a <b>zero-trust API vulnerability scanner</b>. Give it any
              public HTTP(S) API and it probes it for <b>14 vulnerability classes</b>, grades the
              target <b>A&ndash;F</b> (SSL-Labs style), and returns every finding with a
              <b> proof-of-exploit curl command</b> you can run yourself &mdash; plus the OWASP API
              Top&nbsp;10 category and a concrete fix.
            </p>
            <p>
              A compiled <b>Go engine</b> (single static binary, no runtime dependencies) performs
              the actual reconnaissance and exploitation. A <b>FastAPI backend</b> queues scans,
              streams live engine logs over <b>WebSocket</b>, enforces SSRF guards / rate limits,
              and exports <b>HTML, JSON, PDF, SARIF and CSV</b> reports &mdash; or POSTs results to
              a <b>webhook</b> on completion. The whole thing ships as one container.
            </p>
          </section>

          <section>
            <h3>How to use</h3>
            <ol>
              <li><b>Enter a target</b> — an API URL you own or are authorized to test.</li>
              <li><b>Tick the consent box</b> — this is the authorization record and is required.</li>
              <li><b>Pick your checks</b> — all 14 run by default; deselect any you want to skip. Or click <b>&ldquo;scan the live demo target&rdquo;</b> to test the hosted vulnerable sandbox.</li>
              <li><b>Press INITIALIZE SCAN</b> — watch the live terminal stream the engine&rsquo;s progress.</li>
              <li><b>Read the verdict</b> — security grade, severity counts, and a 3D attack-surface graph.</li>
              <li><b>Expand findings</b> — each card shows the endpoint, OWASP mapping, fix, and a copy-paste reproduction command.</li>
              <li><b>Export</b> — download HTML / JSON / PDF / SARIF / CSV, or set a webhook URL to receive results automatically.</li>
              <li><b>Track regressions</b> — rescan the same target; the diff banner shows new vs fixed findings.</li>
            </ol>
          </section>

          <section>
            <h3>14 detection classes</h3>
            <div className="guide-checks">
              {CHECKS.map(([name, desc]) => (
                <div className="guide-check" key={name}>
                  <b>{name}</b>
                  <span>{desc}</span>
                </div>
              ))}
            </div>
          </section>

          <div className="guide-download">
            <a href="/preprint" target="_blank" rel="noreferrer">↓ Download the research preprint (PDF)</a>
          </div>
        </div>
      </div>
    </div>
  )
}
