import { useEffect, useRef, useState } from 'react'
import { API_URL } from '../api.js'

const RISK_STYLES = {
  HIGH: 'bg-clay/20 text-clay border-clay/40',
  MEDIUM: 'bg-amber/15 text-amber border-amber/40',
  LOW: 'bg-forest-light/15 text-forest-light border-forest-light/30',
}

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

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-5">
      <p className="text-[11px] font-medium uppercase tracking-widest text-paper/50">{label}</p>
      <p className={`mt-2 font-serif text-3xl font-medium md:text-4xl ${accent || 'text-paper'}`}>
        {value}
      </p>
    </div>
  )
}

function AlertRow({ alert, refNow }) {
  const riskStyle = RISK_STYLES[alert.risk_level] || RISK_STYLES.LOW
  return (
    <li className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 transition hover:border-white/20">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${riskStyle}`}>
          {alert.risk_level}
        </span>
        <span className="font-serif text-lg font-medium text-paper">{alert.attack_class}</span>
        <span className="rounded-full bg-white/5 px-2 py-0.5 text-[10px] text-paper/60">
          {(alert.confidence * 100).toFixed(1)}%
        </span>
        <span className="ml-auto text-[11px] text-paper/40" title={fmtTime(alert.ts)}>
          {timeAgo(alert.ts, refNow)}
        </span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-paper/50">
        <span className="rounded bg-white/5 px-1.5 py-0.5">device: {alert.device_id || 'default'}</span>
        {alert.src_ip && (
          <span className="rounded bg-white/5 px-1.5 py-0.5 font-mono">src: {alert.src_ip}</span>
        )}
        <span className="rounded bg-white/5 px-1.5 py-0.5">{alert.model_status}</span>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {(alert.defense_actions || []).map((action) => (
          <span key={action} className="rounded-full border border-amber/25 bg-amber/10 px-2 py-0.5 text-[10px] text-amber">
            {action}
          </span>
        ))}
      </div>
    </li>
  )
}

function flagOf(cc) {
  if (!cc || cc.length !== 2) return '🌐'
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
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
  const countries = Object.entries(byCountry).sort((a, b) => b[1].flows - a[1].flows)

  return (
    <section className="mt-6 rounded-3xl border border-white/10 bg-white/[0.03] p-6">
      <div className="flex items-center justify-between">
        <h2 className="font-serif text-xl font-medium">Top source IPs</h2>
        <span className="text-xs text-paper/40">who is talking to this network</span>
      </div>
      <ul className="mt-5 space-y-3">
        {topIps.map((t) => {
          const g = geoMap[t.ip] || {}
          return (
            <li key={t.ip} className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-lg">{flagOf(g.country_code)}</span>
                <span className="font-mono text-sm font-semibold text-paper">{t.ip}</span>
                <span className="text-xs text-paper/50">
                  {g.city ? `${g.city}, ` : ''}{g.country || ''}
                </span>
                <span className="ml-auto rounded-full bg-white/5 px-2 py-0.5 text-[10px] text-paper/60">
                  {t.flows} flows · {t.attacks} attacks
                </span>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10">
                  <div
                    className="h-full rounded-full bg-forest-light"
                    style={{ width: `${(t.flows / maxFlows) * 100}%` }}
                  />
                </div>
                {t.gnn_risk != null && t.gnn_risk > 0 && (
                  <span className="rounded-full border border-amber/30 bg-amber/10 px-2 py-0.5 text-[10px] text-amber">
                    GNN risk {t.gnn_risk}
                  </span>
                )}
              </div>
            </li>
          )
        })}
      </ul>

      {countries.length > 0 && (
        <>
          <h3 className="mt-7 font-serif text-lg font-medium">Location overview</h3>
          <div className="mt-3 flex flex-wrap gap-2">
            {countries.map(([country, v]) => (
              <span
                key={country}
                className="rounded-full border border-white/10 bg-white/5 px-3.5 py-1.5 text-xs text-paper/80"
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
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState(null)
  const [session, setSession] = useState(null)
  const [geoMap, setGeoMap] = useState({})
  const [connected, setConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState(null)
  const [, setTick] = useState(0)
  const pollRef = useRef(null)
  const geoCache = useRef({})

  const apply = (data) => {
    if (!data) return
    setStats(data)
    setLastUpdate(Date.now())
    const ips = (data.top_ips || []).map((t) => t.ip).filter((ip) => ip && !geoCache.current[ip])
    if (ips.length > 0) {
      fetch(`${API_URL}/ai/geo`, {
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
    fetch(`${API_URL}/ai/session`)
      .then((r) => (r.ok ? r.json() : null))
      .then(setSession)
      .catch(() => {})

  const startSession = async () => {
    try {
      await fetch(`${API_URL}/ai/session/start`, { method: 'POST' })
      setSession(await (await fetch(`${API_URL}/ai/session`)).json())
      fetch(`${API_URL}/ai/stats`).then((r) => r.json()).then(setStats).catch(() => {})
    } catch {}
  }

  const stopSession = async () => {
    try {
      await fetch(`${API_URL}/ai/session/stop`, { method: 'POST' })
      setSession(await (await fetch(`${API_URL}/ai/session`)).json())
      fetch(`${API_URL}/ai/stats`).then((r) => r.json()).then(setStats).catch(() => {})
    } catch {}
  }

  useEffect(() => {
    const fetchHistory = () =>
      fetch(`${API_URL}/ai/history?hours=24`)
        .then((r) => (r.ok ? r.json() : null))
        .then(setHistory)
        .catch(() => {})
    const fetchOnce = () =>
      fetch(`${API_URL}/ai/stats`)
        .then((r) => (r.ok ? r.json() : null))
        .then(apply)
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
      es = new EventSource(`${API_URL}/ai/stream`)
      es.onopen = () => {
        setConnected(true)
        stopPolling()
      }
      es.onmessage = (e) => {
        apply(JSON.parse(e.data))
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
  }, [])

  const attacks = stats?.attacks_by_class || {}
  const maxClass = Math.max(1, ...Object.values(attacks))
  const risks = stats?.risk_levels || {}
  const alerts = stats?.recent_alerts || []

  const historyEnabled = history?.enabled
  const historyRows = history?.hours || []
  const nowHour = Math.floor(Date.now() / 3600000)
  const dayBars = []
  for (let h = 23; h >= 0; h--) {
    const bucketTs = (nowHour - h) * 3600
    const row = historyRows.find((r) => Math.floor(r.ts / 3600) === nowHour - h)
    dayBars.push({ ts: bucketTs, flows: row?.flows || 0, attacks: row?.attacks || 0 })
  }
  const maxHourFlows = Math.max(1, ...dayBars.map((b) => b.flows))

  return (
    <div className="min-h-[calc(100vh-73px)] bg-ink text-paper">
      <div className="mx-auto max-w-6xl px-6 py-10">
        {/* Header */}
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-[0.25em] text-amber">
              PredictShield AI
            </p>
            <h1 className="font-serif text-4xl font-medium tracking-tight md:text-5xl">
              Live Threat Monitor
            </h1>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span
              className={`inline-flex h-2.5 w-2.5 rounded-full ${
                connected ? 'animate-pulse bg-forest-light' : 'bg-clay'
              }`}
            />
            <span className={connected ? 'text-forest-light' : 'text-clay'}>
              {connected ? 'LIVE' : 'RECONNECTING…'}
            </span>
            {lastUpdate && (
              <span className="text-xs text-paper/40">upd. {fmtTime(lastUpdate / 1000)}</span>
            )}
          </div>
        </div>

        {/* Session control */}
        {(() => {
          const active = session?.active
          const started = session?.started_at
          const ended = session?.ended_at
          const serverNow = stats?.ts || session?.started_at || Date.now() / 1000
          const durSec = started
            ? Math.max(0, Math.round((active ? serverNow : (ended || serverNow)) - started))
            : 0
          const durTxt = `${String(Math.floor(durSec / 60)).padStart(2, '0')}:${String(durSec % 60).padStart(2, '0')}`
          return (
            <div
              className={`mt-6 flex flex-wrap items-center gap-4 rounded-3xl border p-5 transition ${
                active
                  ? 'border-amber/40 bg-amber/5'
                  : ended
                  ? 'border-forest-light/30 bg-forest-light/5'
                  : 'border-white/10 bg-white/[0.03]'
              }`}
            >
              <div className="flex-1 min-w-[240px]">
                <div className="flex items-center gap-2">
                  {active ? (
                    <>
                      <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-amber" />
                      <span className="font-serif text-lg font-medium text-amber">
                        SESSION LIVE · {durTxt}
                      </span>
                    </>
                  ) : ended ? (
                    <span className="font-serif text-lg font-medium text-forest-light">
                      SESSION COMPLETE · {durTxt}
                    </span>
                  ) : (
                    <span className="font-serif text-lg font-medium text-paper">
                      Ready to monitor
                    </span>
                  )}
                </div>
                <p className="mt-1 text-xs leading-relaxed text-paper/50">
                  {active
                    ? 'Counting every flow and attack SINCE you pressed start - fire your test traffic now.'
                    : ended
                    ? 'Summary frozen. Start a new session to reset the counters.'
                    : 'Press start, then send your test traffic - only what happens after start gets counted.'}
                </p>
              </div>
              {active ? (
                <button
                  onClick={stopSession}
                  className="rounded-full border border-clay/40 bg-clay/20 px-7 py-3 text-sm font-bold text-paper transition hover:bg-clay/40"
                >
                  ■ STOP SESSION
                </button>
              ) : (
                <button
                  onClick={startSession}
                  className="rounded-full bg-amber px-7 py-3 text-sm font-bold text-ink transition hover:bg-amber/90"
                >
                  ▶ START MONITORING
                </button>
              )}
            </div>
          )
        })()}

        {!stats ? (
          <p className="mt-24 text-center text-paper/50">Connecting to the AI engine…</p>
        ) : (
          <>
            {/* Stat cards */}
            <div className="mt-8 grid grid-cols-2 gap-4 md:grid-cols-4">
              <StatCard label="Flows analyzed" value={(stats.flows_total ?? 0).toLocaleString()} />
              <StatCard
                label="Attacks detected"
                value={(stats.attacks_total ?? 0).toLocaleString()}
                accent="text-clay"
              />
              <StatCard label="Active devices" value={stats.active_devices ?? 0} />
              <StatCard
                label="Attacks (1h)"
                value={(stats.attacks_last_hour ?? 0).toLocaleString()}
                accent="text-amber"
              />
            </div>

            <div className="mt-6 grid gap-6 lg:grid-cols-5">
              {/* Attacks by class */}
              <section className="rounded-3xl border border-white/10 bg-white/[0.03] p-6 lg:col-span-2">
                <h2 className="font-serif text-xl font-medium">Attacks by class</h2>
                {Object.keys(attacks).length === 0 ? (
                  <p className="mt-6 text-sm text-paper/40">
                    No attacks detected yet — the network looks quiet.
                  </p>
                ) : (
                  <ul className="mt-5 space-y-3">
                    {Object.entries(attacks).map(([cls, count]) => (
                      <li key={cls}>
                        <div className="mb-1 flex items-center justify-between text-sm">
                          <span className="text-paper/80">{cls}</span>
                          <span className="font-medium text-paper">{count.toLocaleString()}</span>
                        </div>
                        <div className="h-2 overflow-hidden rounded-full bg-white/10">
                          <div
                            className="h-full rounded-full bg-clay transition-all duration-500"
                            style={{ width: `${(count / maxClass) * 100}%` }}
                          />
                        </div>
                      </li>
                    ))}
                  </ul>
                )}

                <h2 className="mt-8 font-serif text-xl font-medium">Risk breakdown</h2>
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
                <p className="mt-6 text-xs leading-relaxed text-paper/40">
                  {session?.active || session?.ended_at
                    ? `${stats.flows_last_hour ?? 0} flows in this session · history persisted in PostgreSQL.`
                    : `${stats.flows_last_hour ?? 0} flows analyzed in the last hour · history persisted in PostgreSQL.`}
                </p>
              </section>

              {/* Live alert feed */}
              <section className="rounded-3xl border border-white/10 bg-white/[0.03] p-6 lg:col-span-3">
                <div className="flex items-center justify-between">
                  <h2 className="font-serif text-xl font-medium">Live alert feed</h2>
                  {connected && (
                    <span className="flex items-center gap-1.5 text-xs text-forest-light">
                      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-forest-light" />
                      streaming
                    </span>
                  )}
                </div>
                {alerts.length === 0 ? (
                  <div className="mt-8 rounded-2xl border border-dashed border-white/15 px-6 py-14 text-center">
                    <span className="mb-3 inline-flex h-12 w-12 items-center justify-center rounded-full bg-forest/30 text-xl">
                      ✦
                    </span>
                    <p className="font-serif text-xl">All clear</p>
                    <p className="mt-1 text-sm text-paper/40">
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

            {/* Top source IPs + location overview */}
            <TopIpsSection topIps={stats?.top_ips} geoMap={geoMap} />

            {/* 24h history (persisted in PostgreSQL) */}
            {historyEnabled && (
              <section className="mt-6 rounded-3xl border border-white/10 bg-white/[0.03] p-6">
                <div className="flex items-center justify-between">
                  <h2 className="font-serif text-xl font-medium">Last 24 hours</h2>
                  <span className="text-xs text-paper/40">persisted in PostgreSQL</span>
                </div>
                <div className="mt-5 flex h-28 items-end gap-1">
                  {dayBars.map((b) => (
                    <div
                      key={b.ts}
                      title={`${new Date(b.ts * 1000).toLocaleTimeString('en-IN', {
                        hour: '2-digit',
                        minute: '2-digit',
                      })} — ${b.flows} flows, ${b.attacks} attacks`}
                      className="relative flex-1 rounded-t bg-white/10"
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
                <div className="mt-2 flex justify-between text-[10px] text-paper/40">
                  <span>24h ago</span>
                  <span className="flex items-center gap-2">
                    <span className="inline-block h-2 w-2 rounded-sm bg-clay" /> attacks
                    <span className="ml-2 inline-block h-2 w-2 rounded-sm bg-white/20" /> benign
                    flows
                  </span>
                  <span>now</span>
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  )
}
