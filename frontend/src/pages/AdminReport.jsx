import { useEffect, useRef, useState } from 'react'
import { API_URL } from '../api.js'

function timeAgo(ts, refNow) {
  const s = Math.max(0, Math.round((refNow || Date.now() / 1000) - ts))
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  return `${Math.floor(m / 60)}h ago`
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString('en-IN', { hour12: false })
}

const RISK_STYLES = {
  HIGH: 'bg-clay/10 text-clay border-clay/30',
  MEDIUM: 'bg-amber/10 text-amber border-amber/30',
  LOW: 'bg-forest/10 text-forest border-forest/20',
}

function flagOf(cc) {
  if (!cc || cc.length !== 2) return '🌐'
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

function AlertRow({ alert, refNow }) {
  const riskStyle = RISK_STYLES[alert.risk_level] || RISK_STYLES.LOW
  return (
    <li className="rounded-2xl border border-ink/10 bg-paper p-4 transition hover:border-forest/30">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${riskStyle}`}
        >
          {alert.risk_level}
        </span>
        <span className="font-serif text-lg font-medium text-ink">{alert.attack_class}</span>
        <span className="rounded-full bg-cream px-2 py-0.5 text-[10px] text-smoke">
          {(alert.confidence * 100).toFixed(1)}%
        </span>
        <span className="ml-auto text-[11px] text-smoke" title={fmtTime(alert.ts)}>
          {timeAgo(alert.ts, refNow)}
        </span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-smoke">
        <span className="rounded bg-cream px-1.5 py-0.5">device: {alert.device_id || 'default'}</span>
        {alert.src_ip && (
          <span className="rounded bg-cream px-1.5 py-0.5 font-mono">src: {alert.src_ip}</span>
        )}
        <span className="rounded bg-cream px-1.5 py-0.5">{alert.model_status}</span>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {(alert.defense_actions || []).map((action) => (
          <span
            key={action}
            className="rounded-full border border-forest/20 bg-forest/5 px-2 py-0.5 text-[10px] text-forest"
          >
            {action}
          </span>
        ))}
      </div>
    </li>
  )
}

function TopIpsSection({ topIps, geoMap }) {
  if (!topIps || topIps.length === 0) {
    return null
  }
  const maxFlows = Math.max(1, ...topIps.map((t) => t.flows))
  const byCountry = {}
  for (const t of topIps) {
    const g = geoMap[t.ip] || {}
    const key = g.country || 'Resolving…'
    byCountry[key] = byCountry[key] || { flows: 0, attacks: 0, cc: g.country_code || '' }
    byCountry[key].flows += t.flows
    byCountry[key].attacks += t.attacks
  }
  const countries = Object.entries(byCountry).sort((a, b) => b[1].attacks - a[1].attacks || b[1].flows - a[1].flows)

  return (
    <section className="rounded-3xl border border-ink/10 bg-cream/30 p-6">
      <div className="flex items-center justify-between">
        <h2 className="font-serif text-xl font-medium text-ink">Top source IPs</h2>
        <span className="text-xs text-smoke">who is talking to this network</span>
      </div>
      <ul className="mt-5 space-y-3">
        {topIps.map((t) => {
          const g = geoMap[t.ip] || {}
          const flagged = t.attacks > 0
          return (
            <li key={t.ip} className="rounded-2xl border border-ink/10 bg-paper p-4 transition hover:border-forest/30">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-lg">{flagOf(g.country_code)}</span>
                <span className="font-mono text-sm font-semibold text-ink">{t.ip}</span>
                <span className="text-xs text-smoke">
                  {g.city ? `${g.city}, ` : ''}{g.country || ''}
                </span>
                {flagged ? (
                  <span className="rounded-full border border-clay/30 bg-clay/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-clay">
                    Flagged
                  </span>
                ) : (
                  <span className="rounded-full border border-forest/20 bg-forest/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-forest">
                    Normal
                  </span>
                )}
                <span className="ml-auto rounded-full bg-cream px-2 py-0.5 text-[10px] text-smoke">
                  {t.flows} flows · {t.attacks} attacks
                </span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink/10">
                <div
                  className={`h-full rounded-full ${flagged ? 'bg-clay' : 'bg-forest/60'}`}
                  style={{ width: `${(t.flows / maxFlows) * 100}%` }}
                />
              </div>
            </li>
          )
        })}
      </ul>

      {countries.length > 0 && (
        <>
          <h3 className="mt-7 font-serif text-lg font-medium text-ink">Location overview</h3>
          <div className="mt-3 flex flex-wrap gap-2">
            {countries.map(([country, v]) => (
              <span
                key={country}
                className="rounded-full border border-ink/10 bg-paper px-3.5 py-1.5 text-xs text-ink"
              >
                {flagOf(v.cc)} {country} — {v.flows} flows
                {v.attacks > 0 && <span className="text-clay"> · {v.attacks} attacks</span>}
              </span>
            ))}
          </div>
        </>
      )}
    </section>
  )
}

export default function AdminReport() {
  const [adminToken, setAdminToken] = useState(() => sessionStorage.getItem('ps_admin_token') || '')
  const [loginForm, setLoginForm] = useState({ username: '', password: '' })
  const [loginError, setLoginError] = useState('')
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState(null)
  const [session, setSession] = useState(null)
  const [geoMap, setGeoMap] = useState({})
  const [connected, setConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState(null)
  const [, setTick] = useState(0)
  const pollRef = useRef(null)
  const geoCache = useRef({})

  const authHeaders = () => (adminToken ? { 'X-Admin-Token': adminToken } : {})
  const adminFetch = (path, opts = {}) =>
    fetch(path, { ...opts, headers: { ...(opts.headers || {}), ...authHeaders() } })

  const handleAdminLogin = async (e) => {
    e.preventDefault()
    setLoginError('')
    try {
      const r = await fetch(`${API_URL}/ai/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginForm),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'Login failed')
      sessionStorage.setItem('ps_admin_token', d.token)
      setAdminToken(d.token)
    } catch (err) {
      setLoginError(err.message)
    }
  }

  const adminLogout = () => {
    sessionStorage.removeItem('ps_admin_token')
    setAdminToken('')
    setStats(null)
    setConnected(false)
  }

  const apply = (data) => {
    if (!data) return
    setStats(data)
    setLastUpdate(Date.now())
    const ips = (data.top_ips || []).map((t) => t.ip).filter((ip) => ip && !geoCache.current[ip])
    if (ips.length > 0) {
      adminFetch(`${API_URL}/ai/geo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips }),
      })
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (d?.results) {
            Object.assign(geoCache.current, d.results)
            setGeoMap({ ...geoCache.current })
          }
        })
        .catch(() => {})
    }
  }

  const fetchSession = () =>
    adminFetch(`${API_URL}/ai/session`)
      .then((r) => (r.ok ? r.json() : null))
      .then(setSession)
      .catch(() => {})

  const startSession = async () => {
    try {
      await adminFetch(`${API_URL}/ai/session/start`, { method: 'POST' })
      setSession(await (await adminFetch(`${API_URL}/ai/session`)).json())
      adminFetch(`${API_URL}/ai/stats`).then((r) => r.json()).then(setStats).catch(() => {})
    } catch {}
  }

  const stopSession = async () => {
    try {
      await adminFetch(`${API_URL}/ai/session/stop`, { method: 'POST' })
      setSession(await (await adminFetch(`${API_URL}/ai/session`)).json())
      adminFetch(`${API_URL}/ai/stats`).then((r) => r.json()).then(setStats).catch(() => {})
    } catch {}
  }

  useEffect(() => {
    if (!adminToken) {
      setStats(null)
      setConnected(false)
      return
    }
    const applyLocal = (data) => {
      if (!data) return
      setStats(data)
      setLastUpdate(Date.now())
      const ips = (data.top_ips || []).map((t) => t.ip).filter((ip) => ip && !geoCache.current[ip])
      if (ips.length > 0) {
        adminFetch(`${API_URL}/ai/geo`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ips }),
        })
          .then((r) => (r.ok ? r.json() : null))
          .then((d) => {
            if (d?.results) {
              Object.assign(geoCache.current, d.results)
              setGeoMap({ ...geoCache.current })
            }
          })
          .catch(() => {})
      }
    }
    const fetchHistory = () =>
      adminFetch(`${API_URL}/ai/history?hours=24`)
        .then((r) => (r.ok ? r.json() : null))
        .then(setHistory)
        .catch(() => {})
    const fetchOnce = () =>
      adminFetch(`${API_URL}/ai/stats`)
        .then((r) => {
          if (r.status === 401) {
            sessionStorage.removeItem('ps_admin_token')
            setAdminToken('')
            return null
          }
          return r.ok ? r.json() : null
        })
        .then(applyLocal)
        .catch(() => {})

    fetchOnce()
    fetchHistory()
    fetchSession()
    const historyTimer = setInterval(fetchHistory, 30000)

    const startPolling = () => {
      if (pollRef.current) return
      fetchOnce()
      pollRef.current = setInterval(fetchOnce, 5000)
    }
    const stopPolling = () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }

    fetchOnce()
    let es = null
    try {
      es = new EventSource(`${API_URL}/ai/stream?token=${encodeURIComponent(adminToken)}`)
      es.onopen = () => {
        setConnected(true)
        stopPolling()
      }
      es.onmessage = (e) => {
        applyLocal(JSON.parse(e.data))
        setConnected(true)
      }
      es.onerror = () => {
        setConnected(false)
        startPolling()
      }
    } catch {
      startPolling()
    }

    const clock = setInterval(() => setTick((t) => t + 1), 1000)
    return () => {
      es?.close()
      stopPolling()
      clearInterval(clock)
      clearInterval(historyTimer)
    }
  }, [adminToken])

  const attacks = stats?.attacks_by_class || {}
  const maxClass = Math.max(1, ...Object.values(attacks))
  const risks = stats?.risk_levels || {}
  const alerts = stats?.recent_alerts || []

  const historyEnabled = history?.enabled
  const historyRows = history?.hours || []
  const nowHour = Math.floor((stats?.ts || Date.now() / 1000) / 3600)
  const dayBars = []
  for (let h = 23; h >= 0; h--) {
    const row = historyRows.find((r) => Math.floor(r.ts / 3600) === nowHour - h)
    dayBars.push({ ts: (nowHour - h) * 3600, flows: row?.flows || 0, attacks: row?.attacks || 0 })
  }
  const maxHourFlows = Math.max(1, ...dayBars.map((b) => b.flows))

  // ---------------------------------------------------------------- admin login
  if (!adminToken) {
    return (
      <div className="flex min-h-[calc(100vh-73px)]">
        <div className="hidden flex-1 flex-col justify-between bg-forest p-12 text-paper lg:flex">
          <div className="flex items-center gap-2">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-paper/10 font-serif text-xl">
              H
            </span>
            <span className="font-serif text-xl font-semibold">
              Home<span className="text-clay">Vlog</span>
            </span>
          </div>
          <div>
            <h2 className="font-serif text-4xl font-medium leading-tight">
              Threat Monitor.
              <br />
              Restricted access.
            </h2>
            <p className="mt-4 max-w-sm text-paper/70">
              Sign in with your administrator account to view live network defences.
            </p>
          </div>
          <p className="text-sm text-paper/50">
            © {new Date().getFullYear()} HomeVlog. All rights reserved.
          </p>
        </div>

        <div className="flex flex-1 items-center justify-center bg-paper px-6 py-16">
          <div className="w-full max-w-md">
            <p className="mb-3 text-xs font-medium uppercase tracking-[0.2em] text-clay">
              Restricted
            </p>
            <h1 className="font-serif text-4xl font-medium tracking-tight text-ink">
              Admin sign in
            </h1>
            <p className="mt-3 text-sm text-smoke">
              Threat Monitor · authorized personnel only.
            </p>

            <form onSubmit={handleAdminLogin} className="mt-8 space-y-5">
              <div>
                <label htmlFor="admin-user" className="mb-2 block text-sm font-medium text-ink">
                  Username
                </label>
                <input
                  id="admin-user"
                  type="email"
                  autoComplete="username"
                  required
                  value={loginForm.username}
                  onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })}
                  placeholder="admin@example.com"
                  className="w-full rounded-xl border border-ink/15 bg-paper px-4 py-3 text-ink placeholder:text-smoke/50 transition focus:border-forest focus:outline-none focus:ring-2 focus:ring-forest/20"
                />
              </div>
              <div>
                <label htmlFor="admin-pass" className="mb-2 block text-sm font-medium text-ink">
                  Password
                </label>
                <input
                  id="admin-pass"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={loginForm.password}
                  onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                  placeholder="••••••••"
                  className="w-full rounded-xl border border-ink/15 bg-paper px-4 py-3 text-ink placeholder:text-smoke/50 transition focus:border-forest focus:outline-none focus:ring-2 focus:ring-forest/20"
                />
              </div>

              {loginError && (
                <p className="rounded-xl border border-clay/30 bg-clay/10 px-4 py-3 text-sm text-clay">
                  {loginError}
                </p>
              )}

              <button
                type="submit"
                className="w-full rounded-xl bg-forest py-3.5 text-sm font-medium text-paper transition hover:bg-forest/90"
              >
                Sign in
              </button>
            </form>
          </div>
        </div>
      </div>
    )
  }

  // ---------------------------------------------------------------- dashboard
  const sessionActive = session?.active
  const sessionStarted = session?.started_at
  const sessionEnded = session?.ended_at
  const serverNow = stats?.ts || sessionStarted || Date.now() / 1000
  const durSec = sessionStarted
    ? Math.max(0, Math.round((sessionActive ? serverNow : sessionEnded || serverNow) - sessionStarted))
    : 0
  const durTxt = `${String(Math.floor(durSec / 60)).padStart(2, '0')}:${String(durSec % 60).padStart(2, '0')}`

  return (
    <div className="min-h-[calc(100vh-73px)]">
      {/* Hero */}
      <section className="relative overflow-hidden bg-forest">
        <div className="pointer-events-none absolute -top-24 right-10 h-72 w-72 rounded-full bg-amber/10 blur-3xl" />
        <div className="relative mx-auto max-w-6xl px-6 py-12">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="mb-3 text-xs font-medium uppercase tracking-[0.25em] text-amber">
                PredictShield
              </p>
              <h1 className="font-serif text-4xl font-medium tracking-tight text-paper md:text-5xl">
                Live Threat Monitor
              </h1>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <button
                onClick={adminLogout}
                className="rounded-full border border-paper/20 px-3 py-1.5 text-xs text-paper/60 transition hover:border-amber hover:text-amber"
                title="Clear admin session"
              >
                admin logout
              </button>
              <span
                className={`inline-flex h-2.5 w-2.5 rounded-full ${
                  connected ? 'animate-pulse bg-amber' : 'bg-clay'
                }`}
              />
              <span className={connected ? 'text-amber' : 'text-clay'}>
                {connected ? 'LIVE' : 'RECONNECTING…'}
              </span>
              {lastUpdate && (
                <span className="text-xs text-paper/50">upd. {fmtTime(lastUpdate / 1000)}</span>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Session control */}
      <section className="border-b border-ink/10 bg-paper">
        <div className="mx-auto max-w-6xl px-6 py-6">
          <div
            className={`flex flex-wrap items-center gap-4 rounded-3xl border p-5 transition ${
              sessionActive
                ? 'border-forest/30 bg-forest/5'
                : sessionEnded
                ? 'border-ink/10 bg-cream/40'
                : 'border-ink/10 bg-cream/40'
            }`}
          >
            <div className="flex-1 min-w-[240px]">
              <div className="flex items-center gap-2">
                {sessionActive ? (
                  <>
                    <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-clay" />
                    <span className="font-serif text-lg font-medium text-ink">
                      Session live · {durTxt}
                    </span>
                  </>
                ) : sessionEnded ? (
                  <span className="font-serif text-lg font-medium text-ink">
                    Session complete · {durTxt}
                  </span>
                ) : (
                  <span className="font-serif text-lg font-medium text-ink">Ready to monitor</span>
                )}
              </div>
              <p className="mt-1 text-xs leading-relaxed text-smoke">
                {sessionActive
                  ? 'Counting every flow and attack since you pressed start — fire your test traffic now.'
                  : sessionEnded
                  ? 'Summary frozen. Start a new session to reset the counters.'
                  : 'Press start, then send your test traffic — only what happens after start gets counted.'}
              </p>
            </div>
            {sessionActive ? (
              <button
                onClick={stopSession}
                className="rounded-full border border-clay/40 bg-clay px-6 py-3 text-sm font-semibold text-paper transition hover:bg-clay-dark"
              >
                Stop session
              </button>
            ) : (
              <button
                onClick={startSession}
                className="rounded-full bg-forest px-7 py-3 text-sm font-semibold text-paper transition hover:bg-forest/90"
              >
                Start monitoring
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Stat cards */}
      <section className="bg-paper">
        <div className="mx-auto max-w-6xl px-6 pt-10">
          {!stats ? (
            <p className="py-16 text-center text-smoke">Connecting to the AI engine…</p>
          ) : (
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              {[
                ['Flows analyzed', (stats.flows_total ?? 0).toLocaleString(), 'text-forest'],
                ['Attacks detected', (stats.attacks_total ?? 0).toLocaleString(), 'text-clay'],
                ['Capture nodes', stats.active_devices ?? 0, 'text-ink'],
                ['Attacks (1h)', (stats.attacks_last_hour ?? 0).toLocaleString(), 'text-amber'],
              ].map(([label, value, accent]) => (
                <div key={label} className="rounded-3xl border border-ink/10 bg-cream/30 p-6 text-center">
                  <p className="font-serif text-3xl font-medium md:text-4xl">
                    <span className={accent}>{value}</span>
                  </p>
                  <p className="mt-1 text-xs uppercase tracking-widest text-smoke">{label}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {stats && (
        <>
          <section className="bg-paper">
            <div className="mx-auto max-w-6xl px-6 py-10">
              <div className="grid gap-6 lg:grid-cols-5">
                {/* Attacks by class */}
                <section className="rounded-3xl border border-ink/10 bg-cream/30 p-6 lg:col-span-2">
                  <h2 className="font-serif text-xl font-medium text-ink">Attacks by class</h2>
                  {Object.keys(attacks).length === 0 ? (
                    <p className="mt-6 text-sm text-smoke">
                      No attacks detected yet — the network looks quiet.
                    </p>
                  ) : (
                    <ul className="mt-5 space-y-3">
                      {Object.entries(attacks).map(([cls, count]) => (
                        <li key={cls}>
                          <div className="mb-1 flex items-center justify-between text-sm">
                            <span className="text-ink">{cls}</span>
                            <span className="font-medium text-ink">{count.toLocaleString()}</span>
                          </div>
                          <div className="h-2 overflow-hidden rounded-full bg-ink/10">
                            <div
                              className="h-full rounded-full bg-clay transition-all duration-500"
                              style={{ width: `${(count / maxClass) * 100}%` }}
                            />
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}

                  <h2 className="mt-8 font-serif text-xl font-medium text-ink">Risk breakdown</h2>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {['HIGH', 'MEDIUM', 'LOW'].map((level) => (
                      <span
                        key={level}
                        className={`rounded-full border px-3.5 py-1.5 text-xs font-semibold ${
                          RISK_STYLES[level]
                        }`}
                      >
                        {level}: {risks[level] ?? 0}
                      </span>
                    ))}
                  </div>
                  <p className="mt-6 text-xs leading-relaxed text-smoke">
                    {sessionActive || sessionEnded
                      ? `${stats.flows_last_hour ?? 0} flows in this session · history persisted in PostgreSQL.`
                      : `${stats.flows_last_hour ?? 0} flows analyzed in the last hour · history persisted in PostgreSQL.`}
                  </p>
                </section>

                {/* Live alert feed */}
                <section className="rounded-3xl border border-ink/10 bg-cream/30 p-6 lg:col-span-3">
                  <div className="flex items-center justify-between">
                    <h2 className="font-serif text-xl font-medium text-ink">Live alert feed</h2>
                    {connected && (
                      <span className="flex items-center gap-1.5 text-xs text-forest">
                        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-forest" />
                        streaming
                      </span>
                    )}
                  </div>
                  {alerts.length === 0 ? (
                    <div className="mt-8 rounded-2xl border border-dashed border-ink/15 bg-cream/20 px-6 py-14 text-center">
                      <span className="mb-3 inline-flex h-12 w-12 items-center justify-center rounded-full bg-forest/10 text-xl text-forest">
                        ✦
                      </span>
                      <p className="font-serif text-xl text-ink">All clear</p>
                      <p className="mt-1 text-sm text-smoke">
                        Attack verdicts will appear here the moment the engine flags one.
                      </p>
                    </div>
                  ) : (
                    <ul className="mt-5 max-h-[520px] space-y-3 overflow-y-auto pr-1">
                      {alerts.map((alert, i) => (
                        <AlertRow key={`${alert.ts}-${i}`} alert={alert} refNow={stats?.ts} />
                      ))}
                    </ul>
                  )}
                </section>
              </div>

              {/* Top source IPs */}
              <TopIpsSection topIps={stats?.top_ips} geoMap={geoMap} />

              {/* 24h history */}
              {historyEnabled && (
                <section className="mt-6 rounded-3xl border border-ink/10 bg-cream/30 p-6">
                  <div className="flex items-center justify-between">
                    <h2 className="font-serif text-xl font-medium text-ink">Last 24 hours</h2>
                    <span className="text-xs text-smoke">persisted in PostgreSQL</span>
                  </div>
                  <div className="mt-5 flex h-28 items-end gap-1">
                    {dayBars.map((b) => (
                      <div
                        key={b.ts}
                        title={`${new Date(b.ts * 1000).toLocaleTimeString('en-IN', {
                          hour: '2-digit',
                          minute: '2-digit',
                        })} — ${b.flows} flows, ${b.attacks} attacks`}
                        className="relative flex-1 rounded-t bg-ink/10"
                        style={{ height: `${Math.max(4, (b.flows / maxHourFlows) * 100)}%` }}
                      >
                        {b.attacks > 0 && (
                          <div
                            className="absolute bottom-0 w-full rounded-t bg-clay"
                            style={{
                              height: `${Math.min(100, (b.attacks / Math.max(1, b.flows)) * 100)}%`,
                            }}
                          />
                        )}
                      </div>
                    ))}
                  </div>
                  <div className="mt-2 flex justify-between text-[10px] text-smoke">
                    <span>24h ago</span>
                    <span className="flex items-center gap-2">
                      <span className="inline-block h-2 w-2 rounded-sm bg-clay" /> attacks
                      <span className="ml-2 inline-block h-2 w-2 rounded-sm bg-forest/40" /> benign
                      flows
                    </span>
                    <span>now</span>
                  </div>
                </section>
              )}
            </div>
          </section>
        </>
      )}
    </div>
  )
}
