import { useState, useEffect } from 'react'
import { useIncidentStore } from '../store/incidents'
import ThreatFeed from '../components/ThreatFeed'
import IncidentTimeline from '../components/IncidentTimeline'
import SeverityBadge from '../components/SeverityBadge'
import { useIncidents } from '../hooks/useIncidents'
import { Link } from 'react-router-dom'

function useNow() {
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return now
}

function StatCard({
  label, value, sub, accent,
}: { label: string; value: string | number; sub?: string; accent: string }) {
  return (
    <div className={`relative bg-slate-900 border border-slate-800 rounded-xl p-4 overflow-hidden`}>
      <div className={`absolute inset-x-0 top-0 h-[2px] ${accent}`} />
      <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">{label}</p>
      <p className="text-2xl font-bold text-slate-100 tabular-nums">{value}</p>
      {sub && <p className="text-[10px] text-slate-600 mt-0.5">{sub}</p>}
    </div>
  )
}

const STATUS_STYLES: Record<string, string> = {
  OPEN:        'text-red-400 bg-red-500/10 ring-1 ring-red-500/40',
  IN_PROGRESS: 'text-yellow-400 bg-yellow-500/10 ring-1 ring-yellow-500/40',
  CLOSED:      'text-slate-500 bg-slate-700/30 ring-1 ring-slate-600/40',
}

export default function Dashboard() {
  const now = useNow()
  const { data: historical, isLoading } = useIncidents({ page_size: 20 })
  const incidents = useIncidentStore((s) => s.incidents)

  const criticalCount = incidents.filter((i) => i.severity === 'CRITICAL').length
  const highCount     = incidents.filter((i) => i.severity === 'HIGH').length
  const avgConf = incidents.length
    ? (incidents.reduce((s, i) => s + i.confidence, 0) / incidents.length * 100).toFixed(1)
    : '—'

  return (
    <div className="min-h-screen flex flex-col bg-slate-950">

      {/* ── Header ─────────────────────────────────────── */}
      <header className="border-b border-slate-800 px-6 py-3 flex items-center gap-4 shrink-0">
        <div className="flex items-center gap-2.5">
          <span className="text-2xl">🛡️</span>
          <span className="text-lg font-black tracking-tight bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
            SENTINELAI
          </span>
        </div>

        <div className="h-4 w-px bg-slate-700 mx-2" />

        <p className="text-xs text-slate-500 hidden sm:block">
          Autonomous Threat Intelligence Platform
        </p>

        <div className="ml-auto flex items-center gap-3">
          <span className="text-xs text-slate-500 tabular-nums hidden md:block">
            {now.toLocaleTimeString()}
          </span>
          <div className="flex items-center gap-1.5 bg-green-500/10 border border-green-500/30 px-2.5 py-1 rounded-full">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-[10px] font-bold text-green-400 uppercase tracking-wider">Live</span>
          </div>
        </div>
      </header>

      {/* ── Metric cards ───────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 px-6 py-4 shrink-0">
        <StatCard
          label="Total Incidents"
          value={historical?.total ?? '—'}
          sub="in database"
          accent="bg-gradient-to-r from-blue-500 to-blue-600"
        />
        <StatCard
          label="Critical"
          value={criticalCount}
          sub="live session"
          accent="bg-gradient-to-r from-red-500 to-red-600"
        />
        <StatCard
          label="High"
          value={highCount}
          sub="live session"
          accent="bg-gradient-to-r from-orange-500 to-orange-600"
        />
        <StatCard
          label="Avg Confidence"
          value={avgConf === '—' ? '—' : `${avgConf}%`}
          sub="live session"
          accent="bg-gradient-to-r from-cyan-500 to-cyan-600"
        />
      </div>

      {/* ── Main panels ─────────────────────────────────── */}
      <div className="flex-none grid grid-cols-2 gap-3 px-6 pb-3 h-[52vh]">
        <div className="bg-slate-900/60 border border-slate-700/50 rounded-xl overflow-hidden flex flex-col">
          <div className="h-[2px] bg-gradient-to-r from-blue-500 to-cyan-500 shrink-0" />
          <ThreatFeed />
        </div>
        <div className="bg-slate-900/60 border border-slate-700/50 rounded-xl overflow-hidden flex flex-col">
          <div className="h-[2px] bg-gradient-to-r from-purple-500 to-pink-500 shrink-0" />
          <IncidentTimeline />
        </div>
      </div>

      {/* ── Historical table ───────────────────────────── */}
      <div className="flex-1 mx-6 mb-6 bg-slate-900/60 border border-slate-700/50 rounded-xl overflow-hidden">
        <div className="h-[2px] bg-gradient-to-r from-slate-600 to-slate-700 shrink-0" />
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">🗂️</span>
            <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Recent Incidents</h2>
          </div>
          {historical?.total !== undefined && (
            <span className="text-[10px] text-slate-500">{historical.total} total</span>
          )}
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-24 text-slate-600 text-xs gap-2">
            <span className="animate-spin">⟳</span> Loading…
          </div>
        ) : (
          <div className="overflow-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-slate-950/90 backdrop-blur-sm">
                <tr className="text-[10px] text-slate-500 uppercase tracking-wider border-b border-slate-800">
                  <th className="text-left px-5 py-2.5">Time</th>
                  <th className="text-left px-4 py-2.5">Severity</th>
                  <th className="text-left px-4 py-2.5">Threat</th>
                  <th className="text-left px-4 py-2.5">Confidence</th>
                  <th className="text-left px-4 py-2.5">Source IP</th>
                  <th className="text-left px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {(historical?.items ?? []).map((inc: any, idx: number) => (
                  <tr
                    key={inc.id}
                    className={`border-b border-slate-800/50 hover:bg-blue-950/20 transition-colors ${idx % 2 === 0 ? '' : 'bg-slate-900/20'}`}
                  >
                    <td className="px-5 py-2.5 text-slate-500 tabular-nums">
                      {new Date(inc.created_at).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={inc.severity} size="sm" />
                    </td>
                    <td className="px-4 py-2.5 font-semibold text-slate-200">{inc.threat_label}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 rounded-full"
                            style={{ width: `${(inc.confidence * 100).toFixed(0)}%` }}
                          />
                        </div>
                        <span className="text-slate-400 tabular-nums">{(inc.confidence * 100).toFixed(1)}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-slate-500 font-mono">{inc.source_ip ?? '—'}</td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${STATUS_STYLES[inc.status] ?? STATUS_STYLES.OPEN}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <Link
                        to={`/incidents/${inc.id}`}
                        className="text-blue-400 hover:text-cyan-400 transition-colors text-[10px] font-semibold"
                      >
                        Details →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(historical?.items ?? []).length === 0 && (
              <div className="flex items-center justify-center h-20 text-slate-700 text-xs">
                No incidents in database yet
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
