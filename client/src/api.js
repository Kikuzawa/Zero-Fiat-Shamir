// Обёртка над REST API сервера-проверяющего.

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'

async function request(path, options = {}) {
  const resp = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  const data = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    throw new Error(data.detail || `Ошибка запроса (${resp.status})`)
  }
  return data
}

export const api = {
  getParams: () => request('/params'),
  register: (username, verifierV, displayName) =>
    request('/register', {
      method: 'POST',
      body: JSON.stringify({ username, verifier_v: verifierV, display_name: displayName }),
    }),
  authStart: (username) =>
    request('/auth/start', { method: 'POST', body: JSON.stringify({ username }) }),
  authCommit: (sessionId, commitmentX, checksum) =>
    request('/auth/commit', {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId, commitment_x: commitmentX, checksum }),
    }),
  authRespond: (sessionId, responseY, checksum) =>
    request('/auth/respond', {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId, response_y: responseY, checksum }),
    }),
  verifyProof: (username, commitments, responses) =>
    request('/auth/verify-proof', {
      method: 'POST',
      body: JSON.stringify({ username, commitments, responses }),
    }),
}
