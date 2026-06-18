import { useEffect, useState } from 'react'
import { api } from './api.js'
import {
  computeVerifier,
  deriveChallenges,
  generateSecret,
  makeCommitment,
  makeResponse,
  valueChecksum,
} from './crypto.js'
import { listIdentities, loadSecret, saveSecret } from './secretStore.js'

const MAX_RESEND = 4 // сколько раз переотправлять раунд при искажении канала

export default function App() {
  const [params, setParams] = useState(null)
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [log, setLog] = useState([])
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [identities, setIdentities] = useState([])
  const [impostor, setImpostor] = useState(false)
  const [mode, setMode] = useState('interactive') // interactive | non-interactive
  const [simulateGlitch, setSimulateGlitch] = useState(false)

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

  // Отправка обязательства с контролем целостности и повтором при искажении.
  // glitchRef.fire — одноразовая имитация сбоя канала (неверная контрольная сумма).
  async function commitWithIntegrity(sessionId, x, glitchRef) {
    for (let attempt = 1; attempt <= MAX_RESEND; attempt++) {
      let checksum = await valueChecksum(x.toString())
      if (glitchRef.fire) {
        glitchRef.fire = false
        checksum = await valueChecksum((x + 1n).toString()) // намеренно неверная сумма
        addLog('Имитация сбоя канала: контрольная сумма обязательства искажена.', 'muted')
      }
      const res = await api.authCommit(sessionId, x.toString(), checksum)
      if (res.integrity_error) {
        addLog(`Сервер обнаружил искажение обязательства — повтор (${attempt}/${MAX_RESEND}).`, 'muted')
        continue
      }
      return res
    }
    throw new Error('Повторные искажения канала при отправке обязательства')
  }

  async function respondWithIntegrity(sessionId, y, glitchRef) {
    for (let attempt = 1; attempt <= MAX_RESEND; attempt++) {
      let checksum = await valueChecksum(y.toString())
      if (glitchRef.fire) {
        glitchRef.fire = false
        checksum = await valueChecksum((y + 1n).toString())
        addLog('Имитация сбоя канала: контрольная сумма отклика искажена.', 'muted')
      }
      const res = await api.authRespond(sessionId, y.toString(), checksum)
      if (res.integrity_error) {
        addLog(`Сервер обнаружил искажение отклика — повтор (${attempt}/${MAX_RESEND}).`, 'muted')
        continue
      }
      return res
    }
    throw new Error('Повторные искажения канала при отправке отклика')
  }

  // Интерактивный режим: пошаговый обмен «обязательство — запрос — отклик».
  async function runInteractive(n, usedSecret) {
    const start = await api.authStart(username)
    addLog(`Старт сессии ${start.session_id.slice(0, 8)}…, раундов: ${start.total_rounds}`)
    // Сбой имитируем один раз на первом раунде (на обязательстве).
    const glitchRef = { fire: simulateGlitch }

    let last = null
    for (let i = 1; i <= start.total_rounds; i++) {
      const { r, x } = makeCommitment(n)
      const commit = await commitWithIntegrity(start.session_id, x, glitchRef)
      const e = commit.challenge_e
      const y = makeResponse(r, usedSecret, e, n)
      const respond = await respondWithIntegrity(start.session_id, y, glitchRef)
      last = respond
      addLog(
        `Раунд ${i}/${start.total_rounds}: запрос e=${e} → ${respond.accepted ? 'принят' : 'отклонён'}`,
        respond.accepted ? 'info' : 'error',
      )
      if (!respond.accepted) break
    }
    return last && last.status === 'success' ? { ok: true, token: last.token } : { ok: false }
  }

  // Неинтерактивный режим: всё доказательство одним пакетом (эвристика Ф–Ш).
  async function runNonInteractive(n, usedSecret) {
    const rounds = params.rounds
    addLog(`Неинтерактивный режим: формируем ${rounds} раундов локально одним пакетом.`)

    const rs = []
    const xs = []
    for (let i = 0; i < rounds; i++) {
      const { r, x } = makeCommitment(n)
      rs.push(r)
      xs.push(x)
    }
    // Запросы сервер выводит из хэша обязательств с открытым верификатором
    // v = s^2 mod n настоящего секрета. Самозванец считает отклики неверным
    // секретом, поэтому они не сойдутся с этими запросами и проверка провалится.
    const realV = computeVerifier(loadSecret(username), n)
    const challenges = await deriveChallenges(n, realV, xs, rounds)
    const ys = xs.map((_, i) => makeResponse(rs[i], usedSecret, challenges[i], n))

    const resp = await api.verifyProof(
      username,
      xs.map((x) => x.toString()),
      ys.map((y) => y.toString()),
    )
    addLog(
      `Пакет отправлен: пройдено ${resp.rounds_completed}/${resp.total_rounds} раундов.`,
      resp.accepted ? 'success' : 'error',
    )
    return resp.status === 'success' ? { ok: true, token: resp.token } : { ok: false }
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
      const usedSecret = impostor ? secret + 1n : secret
      if (impostor) addLog('РЕЖИМ САМОЗВАНЦА: используется неверный секрет (s+1).', 'error')

      const outcome =
        mode === 'non-interactive'
          ? await runNonInteractive(n, usedSecret)
          : await runInteractive(n, usedSecret)

      if (outcome.ok) {
        setResult({ ok: true, token: outcome.token })
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

        <fieldset className="modes">
          <legend>Режим проверки</legend>
          <label className="radio">
            <input type="radio" name="mode" value="interactive"
              checked={mode === 'interactive'} onChange={() => setMode('interactive')} />
            Интерактивный (пошаговый обмен по сети)
          </label>
          <label className="radio">
            <input type="radio" name="mode" value="non-interactive"
              checked={mode === 'non-interactive'} onChange={() => setMode('non-interactive')} />
            Неинтерактивный (одно доказательство одним пакетом)
          </label>
        </fieldset>

        <label className="checkbox">
          <input type="checkbox" checked={impostor} onChange={(e) => setImpostor(e.target.checked)} />
          Войти как самозванец (с неверным секретом) — для проверки стойкости
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={simulateGlitch}
            onChange={(e) => setSimulateGlitch(e.target.checked)} disabled={mode !== 'interactive'} />
          Имитировать сбой канала (проверка контроля целостности) — только для интерактивного режима
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
