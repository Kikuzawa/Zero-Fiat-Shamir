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
      {tab === 'sessions' && <SessionsTable rows={rows} />}
      {tab === 'results' && <ResultsTable rows={rows} />}
      {tab === 'events' && <EventsTable rows={rows} />}
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

function UsersTable({ rows }) {
  return (
    <Table
      columns={['ID', 'Пользователь', 'Имя', 'Активен', 'Верификатор', 'Создан']}
      rows={rows}
      render={(u) => (
        <tr key={u.id}>
          <td>{u.id}</td>
          <td>{u.username}</td>
          <td>{u.display_name || '—'}</td>
          <td>{u.is_active ? 'да' : 'нет'}</td>
          <td>{u.has_verifier ? 'есть' : 'нет'}</td>
          <td>{fmt(u.created_at)}</td>
        </tr>
      )}
    />
  )
}

function SessionsTable({ rows }) {
  return (
    <Table
      columns={['Сессия', 'Пользователь', 'Статус', 'Раунд', 'IP', 'Создана', 'Истекает']}
      rows={rows}
      render={(s) => (
        <tr key={s.session_id}>
          <td className="mono">{s.session_id.slice(0, 8)}…</td>
          <td>{s.username || '—'}</td>
          <td><span className={`badge ${s.status}`}>{STATUS_LABELS[s.status] || s.status}</span></td>
          <td>{s.current_round}/{s.total_rounds}</td>
          <td>{s.client_ip || '—'}</td>
          <td>{fmt(s.created_at)}</td>
          <td>{fmt(s.expires_at)}</td>
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
