// Клиент API администратора. Токен хранится в памяти и в sessionStorage.

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'

function getToken() {
  return sessionStorage.getItem('zerofs:admin-token')
}

export function setToken(token) {
  if (token) sessionStorage.setItem('zerofs:admin-token', token)
  else sessionStorage.removeItem('zerofs:admin-token')
}

async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const resp = await fetch(`${BASE_URL}${path}`, { ...options, headers })
  const data = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    const err = new Error(data.detail || `Ошибка (${resp.status})`)
    err.status = resp.status
    throw err
  }
  return data
}

export const api = {
  login: (username, password) =>
    request('/admin/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  overview: () => request('/admin/overview'),
  users: () => request('/admin/users'),
  sessions: () => request('/admin/sessions'),
  sessionDetail: (sessionId) => request(`/admin/sessions/${sessionId}`),
  results: () => request('/admin/results'),
  events: () => request('/admin/events'),
  hasToken: () => !!getToken(),
}
