import { useEffect, useState } from 'react'
import { api, setToken } from '../api.js'

const TABS = [
  { key: 'overview', label: 'Сводка' },
  { key: 'users', label: 'Пользователи' },
  { key: 'sessions', label: 'Сессии' },
  { key: 'results', label: 'Журнал входов' },
  { key: 'events', label: 'События' },
]

const STATUS_LABELS = {
  awaiting_commitment: 'ожидает обязательство',
  awaiting_response: 'ожидает отклик',
  success: 'успех',
  failed: 'отказ',
  expired: 'истекла',
}

const OUTCOME_LABELS = { success: 'успех', failure: 'отказ', timeout: 'таймаут' }

export default function Dashboard({ onLogout }) {
  const [tab, setTab] = useState('overview')
  const [overview, setOverview] = useState(null)
  const [rows, setRows] = useState([])
  const [error, setError] = useState(null)
  const [selectedSession, setSelectedSession] = useState(null)

  function logout() {
    setToken(null)
    onLogout()
  }

  async function load(currentTab) {
    setError(null)
    try {
      if (currentTab === 'overview') {
        setOverview(await api.overview())
      } else {
        setRows(await api[currentTab]())
      }
    } catch (err) {
      if (err.status === 401) logout()
      else setError(err.message)
    }
  }

  useEffect(() => {
    load(tab)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab])

  return (
    <div className="dashboard">
      <header className="topbar">
        <div>
          <h1>Аутентификация Fiat–Shamir</h1>
          <span className="subtitle">Журнал и мониторинг</span>
        </div>
        <div className="topbar-actions">
          <button onClick={() => load(tab)}>Обновить</button>
          <button onClick={logout}>Выйти</button>
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button key={t.key} className={tab === t.key ? 'active' : ''} onClick={() => setTab(t.key)}>
            {t.label}
          </button>
        ))}
      </nav>

      {error && <p className="error">{error}</p>}

      {tab === 'overview' && overview && <Overview data={overview} />}
      {tab === 'users' && <UsersTable rows={rows} />}
      {tab === 'sessions' && <SessionsTable rows={rows} onInspect={setSelectedSession} />}
      {tab === 'results' && <ResultsTable rows={rows} />}
      {tab === 'events' && <EventsTable rows={rows} />}

      {selectedSession && (
        <SessionModal sessionId={selectedSession} onClose={() => setSelectedSession(null)} />
      )}
    </div>
  )
}

function SessionModal({ sessionId, onClose }) {
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.sessionDetail(sessionId).then(setDetail).catch((e) => setError(e.message))
  }, [sessionId])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>Журнал сессии</h2>
          <button onClick={onClose}>✕</button>
        </div>
        {error && <p className="error">{error}</p>}
        {!detail && !error && <p className="muted">Загрузка…</p>}
        {detail && (
          <div className="modal-body">
            <div className="kv">
              <div><span>Сессия</span><b className="mono">{detail.session_id}</b></div>
              <div><span>Пользователь</span><b>{detail.username || '—'}</b></div>
              <div><span>Статус</span><b><span className={`badge ${detail.status}`}>{STATUS_LABELS[detail.status] || detail.status}</span></b></div>
              <div><span>Раундов пройдено</span><b>{detail.current_round}/{detail.total_rounds}</b></div>
              <div><span>IP / агент</span><b>{detail.client_ip || '—'}</b></div>
              <div><span>Создана</span><b>{fmt(detail.created_at)}</b></div>
            </div>

            <h3>Параметры протокола (Fiat–Shamir)</h3>
            <div className="formula">
              <div>Модуль <code>n</code> = <span className="bignum">{detail.modulus_n}</span></div>
              <div>Верификатор <code>v = s² mod n</code> = <span className="bignum">{detail.verifier_v}</span></div>
              <div className="muted">Секрет <code>s</code> на сервере отсутствует — хранится только у клиента.</div>
            </div>

            <h3>Пораундовые вычисления и проверки</h3>
            <p className="muted">
              В каждом раунде проверяется равенство <code>y² ≡ x·vᵉ (mod n)</code>.
            </p>
            {detail.rounds.length === 0 ? (
              <p className="muted">Раунды ещё не выполнялись.</p>
            ) : (
              detail.rounds.map((r) => (
                <div key={r.round_index} className={`round ${r.verified ? 'ok' : 'fail'}`}>
                  <div className="round-head">
                    Раунд {r.round_index} · запрос <code>e = {r.challenge_e}</code> ·{' '}
                    {r.verified ? '✓ принят' : '✗ отклонён'}
                  </div>
                  <div className="round-row"><span>Обязательство <code>x = r² mod n</code></span><span className="bignum">{r.commitment_x}</span></div>
                  <div className="round-row"><span>Отклик <code>y = r·s^{r.challenge_e} mod n</code></span><span className="bignum">{r.response_y}</span></div>
                  <div className="round-row"><span>Левая часть <code>y² mod n</code></span><span className="bignum">{r.lhs}</span></div>
                  <div className="round-row"><span>Правая часть <code>x·v^{r.challenge_e} mod n</code></span><span className="bignum">{r.rhs}</span></div>
                  <div className="round-verdict">
                    {r.lhs === r.rhs
                      ? 'Левая часть = правой → проверка пройдена'
                      : 'Левая часть ≠ правой → проверка провалена (доказывающий не знает секрет)'}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function Overview({ data }) {
  const cards = [
    { label: 'Пользователей', value: data.users_total },
    { label: 'Активные сессии', value: data.active_sessions },
    { label: 'Неудачные входы (24ч)', value: data.failed_attempts_24h, warn: data.failed_attempts_24h > 0 },
    { label: 'Успешные входы (24ч)', value: data.success_attempts_24h },
    { label: 'Таймауты (24ч)', value: data.timeout_attempts_24h },
    { label: 'Всего попыток', value: data.total_attempts },
    { label: 'Доля успеха', value: `${(data.success_rate * 100).toFixed(1)}%` },
    { label: 'Открытые события', value: data.open_events, warn: data.open_events > 0 },
  ]
  return (
    <div className="cards">
      {cards.map((c) => (
        <div key={c.label} className={`stat ${c.warn ? 'warn' : ''}`}>
          <div className="stat-value">{c.value}</div>
          <div className="stat-label">{c.label}</div>
        </div>
      ))}
    </div>
  )
}

function Table({ columns, rows, render }) {
  if (!rows.length) return <p className="muted">Нет данных.</p>
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr>
        </thead>
        <tbody>{rows.map(render)}</tbody>
      </table>
    </div>
  )
}

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

function LockStatus({ user }) {
  if (!user.locked_until) {
    if (user.consecutive_failures > 0)
      return <span className="badge warning">{user.consecutive_failures} ош.</span>
    return <span className="muted">—</span>
  }
  const until = new Date(user.locked_until)
  const remaining = Math.max(0, Math.round((until - Date.now()) / 1000))
  return (
    <span className="badge failed" title={`до ${until.toLocaleString()}`}>
      заблок. {remaining > 0 ? `(${remaining} с)` : '(истекла)'}
    </span>
  )
}

function UsersTable({ rows }) {
  return (
    <Table
      columns={['ID', 'Пользователь', 'Имя', 'Активен', 'Верификатор', 'Блокировка', 'Создан']}
      rows={rows}
      render={(u) => (
        <tr key={u.id}>
          <td>{u.id}</td>
          <td>{u.username}</td>
          <td>{u.display_name || '—'}</td>
          <td>{u.is_active ? 'да' : 'нет'}</td>
          <td>{u.has_verifier ? 'есть' : 'нет'}</td>
          <td><LockStatus user={u} /></td>
          <td>{fmt(u.created_at)}</td>
        </tr>
      )}
    />
  )
}

function SessionsTable({ rows, onInspect }) {
  return (
    <Table
      columns={['Сессия', 'Пользователь', 'Статус', 'Раунд', 'IP', 'Создана', '']}
      rows={rows}
      render={(s) => (
        <tr key={s.session_id}>
          <td className="mono">{s.session_id.slice(0, 8)}…</td>
          <td>{s.username || '—'}</td>
          <td><span className={`badge ${s.status}`}>{STATUS_LABELS[s.status] || s.status}</span></td>
          <td>{s.current_round}/{s.total_rounds}</td>
          <td>{s.client_ip || '—'}</td>
          <td>{fmt(s.created_at)}</td>
          <td><button className="link-btn" onClick={() => onInspect(s.session_id)}>Подробнее</button></td>
        </tr>
      )}
    />
  )
}

function ResultsTable({ rows }) {
  return (
    <Table
      columns={['ID', 'Пользователь', 'Исход', 'Раунды', 'Детали', 'IP', 'Время']}
      rows={rows}
      render={(r) => (
        <tr key={r.id}>
          <td>{r.id}</td>
          <td>{r.username || '—'}</td>
          <td><span className={`badge ${r.outcome}`}>{OUTCOME_LABELS[r.outcome] || r.outcome}</span></td>
          <td>{r.rounds_completed}/{r.total_rounds}</td>
          <td>{r.detail || '—'}</td>
          <td>{r.client_ip || '—'}</td>
          <td>{fmt(r.created_at)}</td>
        </tr>
      )}
    />
  )
}

function EventsTable({ rows }) {
  return (
    <Table
      columns={['ID', 'Тип', 'Важность', 'Пользователь', 'Сообщение', 'Время']}
      rows={rows}
      render={(e) => (
        <tr key={e.id}>
          <td>{e.id}</td>
          <td>{e.type}</td>
          <td><span className={`badge sev-${e.severity}`}>{e.severity}</span></td>
          <td>{e.username || '—'}</td>
          <td>{e.message}</td>
          <td>{fmt(e.created_at)}</td>
        </tr>
      )}
    />
  )
}
