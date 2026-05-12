import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import { useIncidentStore } from '../store/incidents'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#2563eb',
  INFO: '#16a34a',
}

export default function IncidentTimeline() {
  const incidents = useIncidentStore((s) => s.incidents)

  const data = incidents.slice(0, 200).map((inc) => ({
    time: new Date(inc.created_at).getTime(),
    score: Math.abs(inc.anomaly_score),
    severity: inc.severity,
    label: inc.threat_label,
  }))

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-slate-700">
        <h2 className="text-sm font-semibold text-slate-300">Incident Timeline</h2>
        <p className="text-xs text-slate-500">Anomaly score over time • color = severity</p>
      </div>
      <div className="flex-1 p-2">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 10, right: 20, bottom: 20, left: 10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis
              dataKey="time"
              type="number"
              domain={['auto', 'auto']}
              tickFormatter={(v) => new Date(v).toLocaleTimeString()}
              stroke="#475569"
              tick={{ fontSize: 10, fill: '#94a3b8' }}
              name="Time"
            />
            <YAxis
              dataKey="score"
              name="Anomaly Score"
              stroke="#475569"
              tick={{ fontSize: 10, fill: '#94a3b8' }}
              label={{ value: '|Score|', angle: -90, position: 'insideLeft', fill: '#64748b', fontSize: 10 }}
            />
            <Tooltip
              cursor={{ strokeDasharray: '3 3' }}
              content={({ payload }) => {
                if (!payload?.length) return null
                const d = payload[0].payload
                return (
                  <div className="bg-slate-800 border border-slate-600 rounded p-2 text-xs">
                    <p className="text-slate-200 font-semibold">{d.label}</p>
                    <p className="text-slate-400">Score: {d.score.toFixed(4)}</p>
                    <p className="text-slate-400">{new Date(d.time).toLocaleTimeString()}</p>
                  </div>
                )
              }}
            />
            <Scatter data={data} name="Incidents">
              {data.map((entry, index) => (
                <Cell
                  key={index}
                  fill={SEVERITY_COLORS[entry.severity] ?? '#64748b'}
                  opacity={0.8}
                />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
