import { useParams, Link } from 'react-router-dom'
import { useIncident } from '../hooks/useIncidents'
import SeverityBadge from '../components/SeverityBadge'
import MitreTacticBadge from '../components/MitreTacticBadge'
import ShapWaterfallChart from '../components/ShapWaterfallChart'

const SEVERITY_HERO: Record<string, string> = {
  CRITICAL: 'from-red-950/70 via-slate-950 to-slate-950 border-red-500/30',
  HIGH:     'from-orange-950/70 via-slate-950 to-slate-950 border-orange-500/30',
  MEDIUM:   'from-yellow-950/60 via-slate-950 to-slate-950 border-yellow-500/30',
  LOW:      'from-blue-950/60 via-slate-950 to-slate-950 border-blue-500/30',
  INFO:     'from-green-950/60 via-slate-950 to-slate-950 border-green-500/30',
}

function StatCard({ icon, label, value, mono = false }: {
  icon: string; label: string; value: string; mono?: boolean
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-base">{icon}</span>
        <p className="text-[10px] text-slate-500 uppercase tracking-widest">{label}</p>
      </div>
      <p className={`text-slate-100 font-bold text-lg ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  )
}

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: incident, isLoading, error } = useIncident(id ?? '')

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950">
        <div className="flex flex-col items-center gap-3 text-slate-500">
          <span className="text-3xl animate-spin">⟳</span>
          <p className="text-sm">Loading incident…</p>
        </div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4 bg-slate-950 text-slate-500">
        <span className="text-5xl">🔍</span>
        <p className="text-sm">Incident not found</p>
        <Link to="/" className="text-blue-400 hover:text-cyan-400 transition-colors text-sm">
          ← Back to Dashboard
        </Link>
      </div>
    )
  }

  const shapFeatures = incident.shap_values ?? []
  const heroClasses = SEVERITY_HERO[incident.severity] ?? SEVERITY_HERO.INFO

  return (
    <div className="min-h-screen bg-slate-950">

      {/* ── Hero banner ───────────────────────────────── */}
      <div className={`bg-gradient-to-r ${heroClasses} border-b px-6 py-8`}>
        <Link to="/" className="text-blue-400 hover:text-cyan-400 text-xs transition-colors mb-6 inline-block">
          ← Back to Dashboard
        </Link>

        <div className="flex items-start justify-between gap-6">
          <div className="flex items-start gap-4">
            <SeverityBadge severity={incident.severity} size="lg" />
            <div>
              <h1 className="text-3xl font-black text-slate-100 tracking-tight">{incident.threat_label}</h1>
              <p className="text-slate-500 font-mono text-xs mt-1">{incident.id}</p>
              <p className="text-slate-600 text-xs mt-0.5">
                {new Date(incident.created_at).toLocaleString([], {
                  weekday: 'short', month: 'short', day: 'numeric',
                  hour: '2-digit', minute: '2-digit', second: '2-digit',
                })}
              </p>
            </div>
          </div>

          <a
            href={`/api/reports/${incident.id}`}
            target="_blank"
            rel="noreferrer"
            className="shrink-0 flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-xs font-bold transition-colors shadow-lg shadow-blue-500/20"
          >
            📄 PDF Report
          </a>
        </div>
      </div>

      <div className="px-6 py-6 space-y-6">

        {/* ── Stat cards ───────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatCard icon="🎯" label="Confidence" value={`${(incident.confidence * 100).toFixed(1)}%`} />
          <StatCard icon="📊" label="Anomaly Score" value={incident.anomaly_score.toFixed(4)} />
          <StatCard icon="🔘" label="Status" value={incident.status} />
          <StatCard icon="🌐" label="Source IP" value={incident.source_ip ?? '—'} mono />
          <StatCard icon="🎯" label="Dest IP" value={incident.dest_ip ?? '—'} mono />
        </div>

        {/* ── MITRE ATT&CK ─────────────────────────────── */}
        {incident.mitre_techniques?.length > 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <span>⚔️</span>
              <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider">MITRE ATT&CK Techniques</h2>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {incident.mitre_techniques.map((ttp: any) => (
                <a
                  key={ttp.technique_id}
                  href={ttp.url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-start gap-3 bg-slate-800/60 border border-slate-700/60 hover:border-slate-600 rounded-lg p-3 transition-colors group"
                >
                  <span className="font-mono text-xs text-blue-400 shrink-0 group-hover:text-cyan-400 transition-colors font-bold">
                    {ttp.technique_id}
                  </span>
                  <div className="min-w-0">
                    <p className="text-slate-200 text-xs font-semibold truncate">
                      {ttp.technique_name !== ttp.technique_id ? ttp.technique_name : 'View on MITRE →'}
                    </p>
                    <MitreTacticBadge tactic={ttp.tactic} techniqueId="" />
                  </div>
                </a>
              ))}
            </div>
          </div>
        )}

        {/* ── SHAP Explanation ─────────────────────────── */}
        {shapFeatures.length > 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-2">
              <span>🧠</span>
              <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Explainability</h2>
            </div>
            <ShapWaterfallChart features={shapFeatures} />
          </div>
        )}

      </div>
    </div>
  )
}
