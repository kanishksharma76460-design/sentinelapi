const API_KEY_STORE = 'sentinel_api_key'
const SESSION_STORE = 'sentinel_session'

export function headers(json = false) {
  const h = {}
  if (json) h['Content-Type'] = 'application/json'
  const key = localStorage.getItem(API_KEY_STORE)
  if (key) h['X-API-Key'] = key
  const session = localStorage.getItem(SESSION_STORE)
  if (session) h['Authorization'] = 'Bearer ' + session
  return h
}

export async function authStatus() {
  const r = await fetch('/api/auth/status')
  return r.json()
}

export async function login(username, password) {
  const r = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
  const data = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(data.detail || 'login failed')
  localStorage.setItem(SESSION_STORE, data.token)
  return data
}

export function logout() {
  localStorage.removeItem(SESSION_STORE)
}

export function hasSession() {
  return !!localStorage.getItem(SESSION_STORE)
}

export async function startScan(target, consent, checks, webhookUrl) {
  const r = await fetch('/api/scan', {
    method: 'POST',
    headers: headers(true),
    body: JSON.stringify({ target, consent, checks, webhook_url: webhookUrl || null })
  })
  const data = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`)
  return data
}

export async function getScan(jobId) {
  const r = await fetch('/api/scan/' + jobId, { headers: headers() })
  if (!r.ok) throw new Error('scan fetch failed')
  return r.json()
}

export async function listScans() {
  const r = await fetch('/api/scans', { headers: headers() })
  if (!r.ok) throw new Error('history fetch failed')
  return r.json()
}

export async function getDiff(jobId) {
  const r = await fetch(`/api/scan/${jobId}/diff`, { headers: headers() })
  if (!r.ok) throw new Error('diff fetch failed')
  return r.json()
}

export function wsUrl(jobId) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${location.host}/api/scan/${jobId}/ws`
}

export async function getHealth() {
  const r = await fetch('/api/health', { headers: headers() })
  if (!r.ok) throw new Error('health check failed')
  return r.json()
}

export async function cancelScan(jobId) {
  const r = await fetch(`/api/scan/${jobId}/cancel`, { method: 'POST', headers: headers() })
  return r.ok
}

export async function deleteScan(jobId) {
  const r = await fetch('/api/scan/' + jobId, { method: 'DELETE', headers: headers() })
  return r.ok
}

export function reportUrl(jobId, format) {
  return `/api/scan/${jobId}/${format === 'html' ? 'report' : 'report.' + format}`
}

export const DEMO_TARGET =
  (location.hostname === 'localhost' || location.hostname === '127.0.0.1')
    ? 'http://127.0.0.1:8000'
    : 'https://athera-secure-sandbox-production.up.railway.app'

export const ALL_CHECKS = [
  { id: 'bola', label: 'BOLA / IDOR' },
  { id: 'mass-assignment', label: 'Mass Assignment' },
  { id: 'bfla', label: 'BFLA' },
  { id: 'exposure', label: 'Data Exposure' },
  { id: 'missing-auth', label: 'Broken Auth' },
  { id: 'security-misconfig', label: 'Misconfig' },
  { id: 'rate-limit', label: 'Rate Limit' },
  { id: 'debug-endpoints', label: 'Debug Endpoints' },
  { id: 'jwt', label: 'JWT Analysis' },
  { id: 'sqli', label: 'SQL / NoSQLi' },
  { id: 'cors', label: 'CORS' },
  { id: 'ssrf', label: 'SSRF' },
  { id: 'graphql', label: 'GraphQL' },
  { id: 'spec-audit', label: 'Spec Audit' }
]

export const OWASP = {
  'Broken Object-Level Authorization (BOLA / IDOR)':
    ['API1', 'Broken Object Level Authorization', 'Verify the requester owns the object on every request before returning or modifying it.'],
  'Excessive Data Exposure':
    ['API3', 'Excessive Data Exposure', 'Return only fields declared in the schema; never rely on the client to filter sensitive data.'],
  'Broken Authentication':
    ['API2', 'Broken Authentication', 'Enforce authentication on every protected endpoint — declaring it in the spec is not enough.'],
  'Broken Function Level Authorization':
    ['API5', 'Broken Function Level Authorization', 'Enforce role checks server-side on admin endpoints; never trust client-side roles.'],
  'Mass Assignment':
    ['API6', 'Mass Assignment', 'Whitelist allowed fields on create/update and reject or ignore unknown properties.'],
  'Security Misconfiguration':
    ['API8', 'Security Misconfiguration', 'Remove server-version headers and add X-Content-Type-Options, X-Frame-Options and HSTS.'],
  'Missing Rate Limiting':
    ['API4', 'Unrestricted Resource Consumption', 'Add rate limiting (429 + Retry-After) per client on every endpoint.'],
  'Exposed Debug Endpoint':
    ['API9', 'Improper Inventory Management', 'Remove or lock down debug/staging endpoints in production.'],
  'JWT Signature Not Verified (alg:none)':
    ['API2', 'Broken Authentication', 'Always verify the JWT signature; reject tokens with alg:none or alg:HS256 using a weak secret.'],
  'Weak JWT Signing Secret':
    ['API2', 'Broken Authentication', 'Use a strong, rotated signing key and reject tokens signed with weak/known secrets.'],
  'JWT Has No Expiry':
    ['API2', 'Broken Authentication', 'Set a short exp claim on issued tokens and enforce it on verification.'],
  'SQL Injection':
    ['API8', 'Security Misconfiguration', 'Use parameterized queries / an ORM — never concatenate user input into SQL.'],
  'NoSQL Injection':
    ['API8', 'Security Misconfiguration', 'Sanitize query parameters against NoSQL operators ($ne, $gt) before passing to the database.'],
  'Possible SQL/NoSQL Injection (error response)':
    ['API8', 'Security Misconfiguration', 'Use parameterized queries and avoid reflecting raw query errors.'],
  'CORS Misconfiguration (credentialed reflection)':
    ['API8', 'Security Misconfiguration', 'Use a fixed allow-list of origins; never reflect Origin with Access-Control-Allow-Credentials.'],
  'CORS Misconfiguration (wildcard + credentials)':
    ['API8', 'Security Misconfiguration', 'Never combine Access-Control-Allow-Origin: * with credentials.'],
  'CORS Reflects Arbitrary Origin':
    ['API8', 'Security Misconfiguration', 'Restrict Access-Control-Allow-Origin to a known allow-list.'],
  'Server-Side Request Forgery (SSRF)':
    ['API7', 'Server Side Request Forgery', 'Validate and allow-list outbound URLs; block loopback/link-local/cloud-metadata addresses.'],
  'GraphQL Introspection Enabled':
    ['API9', 'Improper Inventory Management', 'Disable introspection in production and enforce query depth/alias limits.'],
  'Undocumented Endpoint':
    ['API9', 'Improper Inventory Management', 'Keep an up-to-date spec; disable or remove undocumented endpoints.'],
  'OpenAPI Declares No Security Schemes':
    ['API2', 'Broken Authentication', 'Document an authentication mechanism in components.securitySchemes and enforce it.'],
  'Reachable Path Outside Known Spec':
    ['API9', 'Improper Inventory Management', 'Verify the production surface matches the declared spec.'],
}

export const SEV = {
  CRITICAL: { color: '#f43f5e', label: 'Critical' },
  HIGH: { color: '#fb923c', label: 'High' },
  MEDIUM: { color: '#facc15', label: 'Medium' },
  LOW: { color: '#38bdf8', label: 'Low' }
}
