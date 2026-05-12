import { useIncidentStore } from '../store/incidents'
import ThreatFeed from '../components/ThreatFeed'
import IncidentTimeline from '../components/IncidentTimeline'
import SeverityBadge from '../components/SeverityBadge'
import { useIncidents } from '../hooks/useIncidents'
import { Link } from 'react-router-dom'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

function SeverityCountChip({ severity }: { severity: string }) {
  const count = useIncidentStore((s) =>
    s.incidents.filter((i) => i.severity === severity).length,
  )
  return (
    <div className="flex items-center gap-1.5">
      <SeverityBadge severity={severity} size="sm" />
      <span className="text-lg font-bold text-slate-100">{count}</span>
    </div>
  )
}

export default function Dashboard() {
  const { data: historical, isLoading } = useIncidents({ page_size: 20 })

  return (
    <div className="min-h-screen flex flex-col bg-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-3 flex items-center gap-8">
        <h1 className="text-xl font-bold text-blue-400 tracking-tight">
          ⚡ SentinelAI
        </h1>
        <div className="flex items-center gap-6">
          {SEVERITIES.map((sev) => (
            <SeverityCountChip key={sev} severity={sev} />
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2 text-xs text-green-400">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          Live
        </div>
      </header>

      {/* Main layout */}
      <div className="flex-1 grid grid-cols-2 gap-0 divide-x divide-slate-800" style={{ height: 'calc(60vh)' }}>
        <div className="overflow-hidden">
          <ThreatFeed />
        </div>
        <div className="overflow-hidden">
          <IncidentTimeline />
        </div>
      </div>

      {/* Historical incidents table */}
      <div className="border-t border-slate-800 flex-1 overflow-auto">
        <div className="px-6 py-3 border-b border-slate-800">
          <h2 className="text-sm font-semibold text-slate-300">Recent Incidents</h2>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center h-24 text-slate-500 text-sm">
            Loading…
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-400 text-xs border-b border-slate-800">
                <th className="text-left px-4 py-2">Time</th>
                <th className="text-left px-4 py-2">Severity</th>
                <th className="text-left px-4 py-2">Threat</th>
                <th className="text-left px-4 py-2">Confidence</th>
                <th className="text-left px-4 py-2">Source IP</th>
                <th className="text-left px-4 py-2">Status</th>
                <th className="text-left px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {(historical?.items ?? []).map((inc: any) => (
                <tr key={inc.id} className="border-b border-slate-900 hover:bg-slate-900">
                  <td className="px-4 py-2 text-slate-400 text-xs">
                    {new Date(inc.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={inc.severity} size="sm" />
                  </td>
                  <td className="px-4 py-2 font-medium text-slate-200">{inc.threat_label}</td>
                  <td className="px-4 py-2 text-slate-400">
                    {(inc.confidence * 100).toFixed(1)}%
                  </td>
                  <td className="px-4 py-2 text-slate-400 font-mono text-xs">
                    {inc.source_ip ?? '—'}
                  </td>
                  <td className="px-4 py-2">
                    <span className={`text-xs ${inc.status === 'OPEN' ? 'text-red-400' : 'text-slate-500'}`}>
                      {inc.status}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <Link
                      to={`/incidents/${inc.id}`}
                      className="text-blue-400 hover:text-blue-300 text-xs"
                    >
                      Details →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
