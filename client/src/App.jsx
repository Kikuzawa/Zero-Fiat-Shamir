import { useEffect, useState } from 'react'
import { api } from './api.js'
import {
  computeVerifier,
  generateSecret,
  makeCommitment,
  makeResponse,
} from './crypto.js'
import { listIdentities, loadSecret, saveSecret } from './secretStore.js'

export default function App() {
  const [params, setParams] = useState(null)
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [log, setLog] = useState([])
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [identities, setIdentities] = useState([])
  const [impostor, setImpostor] = useState(false)

  useEffect(() => {
    api.getParams().then(setParams).catch((e) => addLog('Ошибка параметров: ' + e.message))
    setIdentities(listIdentities())
  }, [])

  function addLog(message, kind = 'info') {
    setLog((prev) => [...prev, { message, kind, ts: new Date().toLocaleTimeString() }])
  }

  async function handleRegister() {
    if (!username || !params) return
    setBusy(true)
    setResult(null)
    try {
      const n = BigInt(params.modulus_n)
      const secret = generateSecret(n)
      const verifier = computeVerifier(secret, n)
      saveSecret(username, secret)
      setIdentities(listIdentities())
      const res = await api.register(username, verifier.toString(), displayName || null)
      addLog(`Регистрация '${username}': ${res.message}`, 'success')
      addLog('Секрет сгенерирован и сохранён локально. На сервер отправлен только верификатор v.', 'muted')
    } catch (e) {
      addLog('Ошибка регистрации: ' + e.message, 'error')
    } finally {
      setBusy(false)
    }
  }

  async function handleLogin() {
    if (!username || !params) return
    const secret = loadSecret(username)
    if (!secret) {
      addLog(`Для '${username}' нет локального секрета. Сначала зарегистрируйтесь.`, 'error')
      return
    }
    setBusy(true)
    setResult(null)
    try {
      const n = BigInt(params.modulus_n)
      const start = await api.authStart(username)
      addLog(`Старт сессии ${start.session_id.slice(0, 8)}…, раундов: ${start.total_rounds}`)

      // В режиме самозванца используем неверный секрет (s+1) — имитация стороны,
      // не знающей настоящий секрет. Такой вход проваливается на первом e=1.
      const usedSecret = impostor ? secret + 1n : secret
      if (impostor) addLog('РЕЖИМ САМОЗВАНЦА: используется неверный секрет (s+1).', 'error')

      let last = null
      for (let i = 1; i <= start.total_rounds; i++) {
        const { r, x } = makeCommitment(n)
        const commit = await api.authCommit(start.session_id, x.toString())
        const e = commit.challenge_e
        const y = makeResponse(r, usedSecret, e, n)
        const respond = await api.authRespond(start.session_id, y.toString())
        last = respond
        addLog(`Раунд ${i}/${start.total_rounds}: запрос e=${e} → ${respond.accepted ? 'принят' : 'отклонён'}`,
          respond.accepted ? 'info' : 'error')
        if (!respond.accepted) break
      }

      if (last && last.status === 'success') {
        setResult({ ok: true, token: last.token })
        addLog('Аутентификация успешна. Получен сессионный токен.', 'success')
      } else {
        setResult({ ok: false })
        addLog('Аутентификация отклонена.', 'error')
      }
    } catch (e) {
      addLog('Ошибка аутентификации: ' + e.message, 'error')
      setResult({ ok: false })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="container">
      <header>
        <h1>Аутентификация с нулевым разглашением</h1>
        <p className="subtitle">Протокол Фиата–Шамира · клиент-доказывающий</p>
      </header>

      <section className="card params">
        <h2>Открытые параметры</h2>
        {params ? (
          <ul>
            <li>Длина модуля: <b>{params.bits} бит</b></li>
            <li>Число раундов: <b>{params.rounds}</b></li>
            <li className="mono">n = {params.modulus_n.slice(0, 40)}…</li>
          </ul>
        ) : (
          <p>Загрузка параметров…</p>
        )}
      </section>

      <section className="card">
        <h2>Идентификация</h2>
        <label>
          Имя пользователя
          <input value={username} onChange={(e) => setUsername(e.target.value)}
            placeholder="например, alice" />
        </label>
        <label>
          Отображаемое имя (необязательно)
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={impostor} onChange={(e) => setImpostor(e.target.checked)} />
          Войти как самозванец (с неверным секретом) — для проверки стойкости
        </label>
        <div className="buttons">
          <button onClick={handleRegister} disabled={busy || !username}>Зарегистрироваться</button>
          <button onClick={handleLogin} disabled={busy || !username} className="primary">Войти</button>
        </div>
        {identities.length > 0 && (
          <p className="muted">Локальные секреты: {identities.join(', ')}</p>
        )}
      </section>

      {result && (
        <section className={`card result ${result.ok ? 'ok' : 'fail'}`}>
          <h2>{result.ok ? '✓ Доступ разрешён' : '✗ Доступ запрещён'}</h2>
          {result.ok && result.token && (
            <p className="mono">Токен: {result.token.slice(0, 24)}…</p>
          )}
        </section>
      )}

      <section className="card">
        <h2>Журнал протокола</h2>
        <div className="log">
          {log.length === 0 && <p className="muted">Действий пока нет.</p>}
          {log.map((entry, i) => (
            <div key={i} className={`log-line ${entry.kind}`}>
              <span className="ts">{entry.ts}</span> {entry.message}
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
