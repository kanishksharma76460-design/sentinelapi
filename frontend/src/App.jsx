import { useEffect, useRef, useState } from 'react'
import AttackGraph from './components/AttackGraph.jsx'
import Eye from './components/Eye.jsx'
import Logo from './components/Logo.jsx'
import RobotFace from './components/RobotFace.jsx'
import SynthGrid from './components/SynthGrid.jsx'
import {
  ALL_CHECKS, DEMO_TARGET, OWASP, SEV,
  startScan, getScan, listScans, getHealth, cancelScan, deleteScan, reportUrl,
  getDiff, wsUrl, authStatus, login, logout, hasSession
} from './api.js'

const STAGES = ['TARGETING', 'PROBING', 'EXPLOITING', 'GRADING']

const BOOT_LINES = [
  '> CALIBRATING OPTIC SENSOR ............ OK',
  '> LOADING SCAN ENGINE v2.4 ............ OK',
  '> ARMING 8 VULNERABILITY CLASSES ...... OK',
  '> SPOOLING PROOF-OF-EXPLOIT ENGINE .... OK',
  '> ESTABLISHING ZERO-TRUST SHELL ....... OK',
  '> AEGIS SYSTEM // ONLINE',
]

function stageFrom(logs, findings) {
  const txt = (logs || []).join(' ')
  if (txt.includes('finding(s):') || (findings && findings.length)) return 2
  if (txt.includes('registered')) return 1
  return 0
}

function gradeLabel(g) {
  if (!g) return ''
  return `${g.grade} · ${g.score}/100`
}

function FindingCard({ f }) {
  const s = SEV[f.severity] || SEV.LOW
  const ow = OWASP[f.title] || ['API', 'OWASP API Top 10', 'Review against the OWASP API Security Top 10.']
  return (
    <div className="finding" style={{ '--sev': s.color }}>
      <div className="top">
        <span className="sev" style={{ background: s.color }}>{f.severity}</span>
        <span className="title">{f.title}</span>
      </div>
      <div className="endpoint">{f.endpoint}</div>
      <p className="detail">{f.detail}</p>
      <div className="owasp"><span className="tag">{ow[0]}</span><b>{ow[1]}</b></div>
      <div className="fix"><b>Fix:</b> {ow[2]}</div>
      <div className="curl">{f.reproduction}</div>
    </div>
  )
}

export default function App() {
  const [target, setTarget] = useState('')
  const [consent, setConsent] = useState(false)
  const [checks, setChecks] = useState(() => new Set(ALL_CHECKS.map(c => c.id)))
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState('')
  const [logs, setLogs] = useState([])
  const [stage, setStage] = useState(0)
  const [findings, setFindings] = useState(null)
  const [grade, setGrade] = useState(null)
  const [history, setHistory] = useState([])
  const [apiKey, setApiKey] = useState(() => localStorage.getItem('sentinel_api_key') || '')
  const [booted, setBooted] = useState(false)
  const [bootGone, setBootGone] = useState(false)
  const [bootLine, setBootLine] = useState(0)
  const [gateOpen, setGateOpen] = useState(false)
  const [gateClosing, setGateClosing] = useState(false)
  const [terminated, setTerminated] = useState(false)
  const [health, setHealth] = useState(null)
  const [webhookUrl, setWebhookUrl] = useState('')
  const [diff, setDiff] = useState(null)
  const [lastJobId, setLastJobId] = useState(null)
  const [needsLogin, setNeedsLogin] = useState(false)
  const [sessionOn, setSessionOn] = useState(hasSession())
  const [loginUser, setLoginUser] = useState('')
  const [loginPass, setLoginPass] = useState('')
  const [loginError, setLoginError] = useState('')
  const termRef = useRef(null)
  const wsRef = useRef(null)

  function finishBoot() {
    setBooted(true)
    setTimeout(() => setBootGone(true), 550)
  }

  function proceed() {
    setGateClosing(true)
    setTimeout(() => setGateOpen(true), 850)
  }

  function terminate() {
    setTerminated(true)
    try { window.close() } catch { /* tab stays open — terminated screen shows */ }
  }

  function restoreSession() {
    setTerminated(false)
    setGateOpen(false)
    setGateClosing(false)
  }

  useEffect(() => { loadHistory() }, [])
  useEffect(() => {
    getHealth().then(setHealth).catch(() => setHealth({ engine: false }))
  }, [])
  useEffect(() => {
    authStatus().then(s => {
      if (s.login_required && !hasSession()) setNeedsLogin(true)
    }).catch(() => {})
  }, [])
  useEffect(() => {
    if (!gateOpen) return
    const t = setTimeout(finishBoot, 2100)
    return () => clearTimeout(t)
  }, [gateOpen])
  useEffect(() => {
    if (!gateOpen) return
    const iv = setInterval(() => setBootLine(l => Math.min(l + 1, BOOT_LINES.length - 1)), 300)
    return () => clearInterval(iv)
  }, [gateOpen])
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [logs])

  async function loadHistory() {
    try {
      const d = await listScans()
      setHistory(d.scans || [])
    } catch { /* backend unreachable */ }
  }

  function toggleCheck(id) {
    setChecks(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function saveApiKey() {
    if (apiKey.trim()) localStorage.setItem('sentinel_api_key', apiKey.trim())
    else localStorage.removeItem('sentinel_api_key')
  }

  async function doLogin() {
    setLoginError('')
    try {
      await login(loginUser.trim(), loginPass)
      setNeedsLogin(false)
      setSessionOn(true)
      loadHistory()
    } catch (e) {
      setLoginError(e.message)
    }
  }

  function doLogout() {
    logout()
    setSessionOn(false)
    if (needsLogin) setNeedsLogin(true)
    else window.location.reload()
  }

  function showTerminal() {
    setLogs([])
    setStage(0)
    setFindings(null)
    setGrade(null)
    setError('')
    setLogs([
      '>> initializing sentinel engine v2.0.0',
      '>> establishing zero-trust channel…'
    ])
  }

  function attachWS(jobId) {
    try {
      const ws = new WebSocket(wsUrl(jobId))
      wsRef.current = ws
      ws.onmessage = ev => {
        if (ev.data.startsWith('__DONE__:')) return
        setLogs(prev => [...prev, ev.data])
      }
      ws.onerror = () => { wsRef.current = null }
      ws.onclose = () => { wsRef.current = null }
    } catch {
      wsRef.current = null
    }
  }

  async function poll(jobId) {
    attachWS(jobId)
    for (;;) {
      await new Promise(r => setTimeout(r, 700))
      let data
      try { data = await getScan(jobId) } catch { continue }
      if (!wsRef.current && data.logs && data.logs.length) {
        // WebSocket fallback: sync logs from polling
        setLogs(prev => {
          const base = prev.filter(l => l.startsWith('>>'))
          return [...base, ...data.logs]
        })
      }
      if (data.status === 'queued' || data.status === 'running') {
        setStage(stageFrom(data.logs, data.findings))
        continue
      }
      if (data.status === 'error') {
        if (wsRef.current) wsRef.current.close()
        setScanning(false)
        setError(data.error || 'scan failed')
        return
      }
      if (wsRef.current) wsRef.current.close()
      setStage(3)
      setFindings(data.findings)
      setGrade(data.grade)
      setLastJobId(jobId)
      setScanning(false)
      loadHistory()
      try { setDiff(await getDiff(jobId)) } catch { setDiff(null) }
      return
    }
  }

  async function runScan(t, c, chk, wh) {
    setError('')
    showTerminal()
    setScanning(true)
    try {
      const data = await startScan(t, c, chk, wh || null)
      poll(data.job_id)
    } catch (e) {
      setScanning(false)
      setError(e.message)
    }
  }

  async function doScan() {
    if (!target.trim()) { setError('Target URL is required'); return }
    if (!consent) { setError('Confirm authorization before scanning'); return }
    await runScan(target.trim(), consent, [...checks], webhookUrl)
  }

  function demo() {
    setTarget(DEMO_TARGET)
    setConsent(true)
    runScan(DEMO_TARGET, true, [...checks], webhookUrl)
  }

  async function removeScan(id) {
    if (!window.confirm('Delete this scan from history?')) return
    if (await deleteScan(id)) loadHistory()
  }

  const counts = findings
    ? findings.reduce((a, f) => (a[f.severity] = (a[f.severity] || 0) + 1, a), {})
    : {}

  return (
    <div className="app">
      <SynthGrid />

      {/* ── Access gate (robot face) ── */}
      {terminated ? (
        <div className="gate-overlay">
          <div className="gate-term">
            <div className="gate-term-glyph">⏻</div>
            <div className="gate-term-title">CONNECTION TERMINATED</div>
            <p className="gate-term-sub">Session terminated by operator. All systems powered down.</p>
            <button className="gate-btn restore" onClick={restoreSession}>↻ RESTORE SESSION</button>
          </div>
        </div>
      ) : !gateOpen && (
        <div className={'gate-overlay' + (gateClosing ? ' closing' : '')}>
          <div className="gate-stage">
            <div className="gate-top">
              <span className="gate-label">AEGIS // ACCESS GATE</span>
              <span className="gate-status"><span className="dot" /> {gateClosing ? 'AUTHENTICATING' : 'STANDBY'}</span>
            </div>
            <RobotFace powering={gateClosing} />
            <div className="gate-name">AEGIS-9 <span className="dim">// Autonomous Security Sentinel</span></div>
            <div className="gate-actions">
              <button className="gate-btn terminate" onClick={terminate}>✕ TERMINATE</button>
              <button className="gate-btn proceed" onClick={proceed} disabled={gateClosing}>▶ PROCEED</button>
            </div>
            <div className="gate-hint">Proceeding initiates the zero-trust boot sequence.</div>
          </div>
        </div>
      )}

      {gateOpen && !bootGone && (
        <div className={'boot' + (booted ? ' hide' : '')} onClick={finishBoot}>
          <div className="boot-logo"><Logo size={76} /></div>
          <div className="boot-text">AEGIS SYSTEM // INITIALIZING</div>
          <div className="boot-log">
            {BOOT_LINES.slice(0, bootLine + 1).map((l, i) => (
              <div key={i} className={'boot-line' + (i === bootLine ? ' active' : '')}>
                {i === bootLine ? <span className="cursor">▌</span> : <span className="boot-ok">·</span>}
                {l}
              </div>
            ))}
          </div>
          <div className="boot-bar"><i /></div>
          <div className="boot-pct">{String(Math.min(99, Math.round(((bootLine + 1) / BOOT_LINES.length) * 100))).padStart(2, '0')}%</div>
        </div>
      )}

      {needsLogin && (
        <div className="login-overlay">
          <div className="login-card bracket">
            <div className="login-logo"><Logo size={58} /></div>
            <div className="login-title">AUTHENTICATION REQUIRED</div>
            <input type="text" value={loginUser} onChange={e => setLoginUser(e.target.value)}
              placeholder="username" autoFocus spellCheck={false} />
            <input type="password" value={loginPass} onChange={e => setLoginPass(e.target.value)}
              placeholder="password" onKeyDown={e => e.key === 'Enter' && doLogin()} />
            <button className="btn" onClick={doLogin}>Authenticate</button>
            {loginError && <div className="error">{loginError}</div>}
          </div>
        </div>
      )}

      {/* ── Nav ── */}
      <nav className="nav">
        <div className="logo">
          <span className="mark"><Logo size={30} /></span>
          <span>Athera <span className="dim">Secure</span></span>
        </div>
        <div className="nav-links">
          <a href="#scan">Scan</a>
          <a href="#results">Results</a>
          <a href="#history">History</a>
          {sessionOn && <button onClick={doLogout}>Logout</button>}
          <input
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            onBlur={saveApiKey}
            placeholder="API key"
            style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-strong)', borderRadius: 8, color: '#f4f4f5', padding: '7px 10px', fontSize: 12, width: 130, fontFamily: 'var(--mono)' }}
          />
        </div>
      </nav>

      {/* ── Hero ── */}
      <section className="hero" id="scan">
        <div className="eyes-row">
          <Eye open={booted} scanning={scanning} done={!!findings} grade={grade} />
          <Eye open={booted} scanning={scanning} done={!!findings} grade={grade} />
        </div>
        <div className="hero-copy">
          <span className={'eyebrow' + (!health || !health.engine ? ' down' : '')}>
            <span className="dot" />
            {!health ? 'AEGIS SYSTEM // LINKING…' : health.engine ? 'AEGIS SYSTEM // ONLINE' : 'AEGIS SYSTEM // ENGINE OFFLINE'}
          </span>
          <h1>Find what your API <span className="accent">leaks.</span></h1>
          <p>
            Athera Secure scans any API for broken access control, leaked data and
            weak authentication — eight vulnerability classes, graded A–F, with
            proof you can run yourself.
          </p>

          <div className="scan-box">
            <div className="scan-row">
              <input
                type="text"
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && doScan()}
                placeholder="https://api.yourdomain.com"
                spellCheck={false}
              />
              <button className="btn" onClick={doScan} disabled={scanning}>
                {scanning ? 'Scanning…' : 'Initialize Scan'}
              </button>
            </div>
            <div className="demo-link">
              or <button onClick={demo}>scan the live demo target</button> (vulnerable sandbox)
            </div>

            <label className="consent">
              <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />
              I confirm ownership &amp; authorization to scan this target.
            </label>

            <input
              className="webhook"
              type="text"
              value={webhookUrl}
              onChange={e => setWebhookUrl(e.target.value)}
              placeholder="Webhook URL (optional) — POSTed when the scan completes"
              spellCheck={false}
            />

            <div className="checks">
              {ALL_CHECKS.map(c => (
                <label key={c.id} className={'check' + (checks.has(c.id) ? ' on' : '')}>
                  <input type="checkbox" checked={checks.has(c.id)} onChange={() => toggleCheck(c.id)} />
                  {c.label}
                </label>
              ))}
            </div>

            {error && <div className="error">{error}</div>}
          </div>
        </div>
      </section>

      {/* ── Terminal ── */}
      {(scanning || logs.length > 0) && (
        <section className="terminal">
          <div className="terminal-head">
            <span className="dots"><i /><i /><i /></span>
            <span className="t">sentinel://live-recon</span>
            <span className="stage">{STAGES[stage]}</span>
          </div>
          <div className="terminal-body" ref={termRef}>
            {logs.map((l, i) => (
              <div key={i} className={'ln ' + (l.startsWith('[!]') ? 'err' : l.startsWith('>>') || l.startsWith('[+]') ? 'ok' : '')}>{l}</div>
            ))}
            {scanning && <div className="ln ok">▋</div>}
          </div>
        </section>
      )}

      {/* ── Results ── */}
      {findings && (
        <section className="section" id="results">
          <div className="panel result-hero">
            <div className={'stamp' + (grade && grade.grade !== 'A' ? ' threat' : '')}>
              {grade && grade.grade === 'A' ? 'ACCESS GRANTED' : 'ANALYSIS COMPLETE'}
            </div>
            {grade && (
              <div className="grade">
                <div className="letter">{grade.grade}</div>
                <div className="meta">
                  <b>Security Grade</b>
                  <span>{grade.score}/100 · {findings.length} findings</span>
                </div>
              </div>
            )}
            <div className="stats">
              <div className="stat"><div className="n" style={{ color: '#f4f4f5' }}>{findings.length}</div><div className="l">Total</div></div>
              <div className="stat"><div className="n" style={{ color: '#f43f5e' }}>{counts.CRITICAL || 0}</div><div className="l">Critical</div></div>
              <div className="stat"><div className="n" style={{ color: '#fb923c' }}>{counts.HIGH || 0}</div><div className="l">High</div></div>
              <div className="stat"><div className="n" style={{ color: '#facc15' }}>{counts.MEDIUM || 0}</div><div className="l">Medium</div></div>
              <div className="stat"><div className="n" style={{ color: '#38bdf8' }}>{counts.LOW || 0}</div><div className="l">Low</div></div>
            </div>
          </div>

          {diff && diff.baseline && (diff.new_count > 0 || diff.fixed_count > 0) && (
            <div className="diff-banner">
              <b>Regression diff</b>
              <span className="diff-new">+{diff.new_count} new</span>
              <span className="diff-fixed">−{diff.fixed_count} fixed</span>
              <span className="diff-same">{diff.unchanged} unchanged</span>
              <span className="diff-sub">vs previous scan of this target</span>
            </div>
          )}

          {findings.length ? (
            <>
              <div className="section">
                <div className="section-head"><h2>Attack Surface</h2><span className="sub">Live 3D map of vulnerable endpoints</span></div>
                <div className="panel"><AttackGraph findings={findings} /></div>
              </div>
              <div className="section">
                <div className="section-head"><h2>Findings</h2><span className="sub">{findings.length} detected</span></div>
                <div className="findings">
                  {findings.map((f, i) => <FindingCard key={i} f={f} />)}
                </div>
              </div>
            </>
          ) : (
            <div className="empty">
              <div className="ico">✦</div>
              <b>No vulnerabilities detected</b>
              <p>Your target passed all eight checks.</p>
            </div>
          )}
        </section>
      )}

      {/* ── History ── */}
      <section className="section" id="history">
        <div className="section-head"><h2>Scan History</h2><span className="sub">Recent targets</span></div>
        <div className="history">
          {history.length === 0 && <div className="empty"><p>No scans yet — run your first scan above.</p></div>}
          {history.map(s => (
            <div className="hrow" key={s.job_id}>
              <span className="t">{s.target}</span>
              {s.status === 'done' && s.grade && <span className="g" style={{ color: '#fbbf24' }}>{s.grade.grade}</span>}
              <span className="meta">{s.status === 'done' ? `${s.findings} findings` : s.status}</span>
              {s.status === 'done' && s.counts && (
                <span className="sevcounts">
                  {[['CRITICAL', '#f43f5e'], ['HIGH', '#fb923c'], ['MEDIUM', '#facc15'], ['LOW', '#38bdf8']]
                    .filter(([k]) => s.counts[k] > 0)
                    .map(([k, col]) => <i key={k} style={{ color: col }}>{s.counts[k]}{k[0]}</i>)}
                </span>
              )}
              <div className="acts">
                {s.status === 'done' && (
                  <>
                    <a href={reportUrl(s.job_id, 'html')}>HTML</a>
                    <a href={reportUrl(s.job_id, 'json')}>JSON</a>
                    <a href={reportUrl(s.job_id, 'pdf')}>PDF</a>
                    <a href={reportUrl(s.job_id, 'sarif')}>SARIF</a>
                    <a href={reportUrl(s.job_id, 'csv')}>CSV</a>
                  </>
                )}
                {(s.status === 'queued' || s.status === 'running') && (
                  <button onClick={() => cancelScan(s.job_id).then(loadHistory)}>Cancel</button>
                )}
                <button className="del" onClick={() => removeScan(s.job_id)}>✕</button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="footer">
        <div className="links">
          <a href="https://github.com/kanishksharma76460-design/sentinelapi" target="_blank" rel="noreferrer">GitHub</a>
          <a href="https://athera-secure-production.up.railway.app" target="_blank" rel="noreferrer">Live App</a>
          <a href="https://athera-secure-sandbox-production.up.railway.app" target="_blank" rel="noreferrer">Demo Target</a>
        </div>
        Athera Secure · Zero-Trust API Security · 2026
      </footer>
    </div>
  )
}
