import {
  ScatterChart, Scatter, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts'
import { useIncidentStore } from '../store/incidents'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#3b82f6',
  INFO:     '#22c55e',
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
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-700/60">
        <span className="text-cyan-400">📡</span>
        <div>
          <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Anomaly Timeline</h2>
          <p className="text-[10px] text-slate-500">Score magnitude · dot color = severity</p>
        </div>
      </div>

      <div className="flex-1 p-3">
        {data.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-600">
            <span className="text-4xl">📊</span>
            <p className="text-xs text-slate-700">Timeline populates as events arrive</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart margin={{ top: 8, right: 16, bottom: 24, left: 0 }}>
              <XAxis
                dataKey="time"
                type="number"
                domain={['auto', 'auto']}
                tickFormatter={(v) => new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                stroke="#1e293b"
                tick={{ fontSize: 9, fill: '#64748b' }}
              />
              <YAxis
                dataKey="score"
                stroke="#1e293b"
                tick={{ fontSize: 9, fill: '#64748b' }}
                width={36}
              />
              <Tooltip
                cursor={false}
                content={({ payload }) => {
                  if (!payload?.length) return null
                  const d = payload[0].payload
                  return (
                    <div className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs shadow-xl">
                      <p className="text-slate-100 font-bold mb-1">{d.label}</p>
                      <p className="text-slate-400">Score: <span className="text-slate-200">{d.score.toFixed(3)}</span></p>
                      <p className="text-slate-400">{new Date(d.time).toLocaleTimeString()}</p>
                    </div>
                  )
                }}
              />
              <Scatter data={data} r={5}>
                {data.map((entry, index) => (
                  <Cell
                    key={index}
                    fill={SEVERITY_COLORS[entry.severity] ?? '#64748b'}
                    opacity={0.85}
                    stroke={SEVERITY_COLORS[entry.severity] ?? '#64748b'}
                    strokeWidth={0.5}
                    strokeOpacity={0.3}
                  />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
