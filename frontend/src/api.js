const API_KEY_STORE = 'sentinel_api_key'

export function headers(json = false) {
  const h = {}
  if (json) h['Content-Type'] = 'application/json'
  const key = localStorage.getItem(API_KEY_STORE)
  if (key) h['X-API-Key'] = key
  return h
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
  { id: 'debug-endpoints', label: 'Debug Endpoints' }
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
    ['API9', 'Improper Inventory Management', 'Remove or lock down debug/staging endpoints in production.']
}

export const SEV = {
  CRITICAL: { color: '#f43f5e', label: 'Critical' },
  HIGH: { color: '#fb923c', label: 'High' },
  MEDIUM: { color: '#facc15', label: 'Medium' },
  LOW: { color: '#38bdf8', label: 'Low' }
}
