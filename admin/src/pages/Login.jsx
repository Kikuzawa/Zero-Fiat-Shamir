import { useState } from 'react'
import { api, setToken } from '../api.js'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = await api.login(username, password)
      setToken(res.token)
      onLogin()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <h1>Панель администратора</h1>
        <p className="subtitle">Система аутентификации Fiat–Shamir</p>
        <label>
          Логин
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          Пароль
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <p className="error">{error}</p>}
        <button className="primary" disabled={busy}>Войти</button>
      </form>
    </div>
  )
}
