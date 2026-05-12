import { useParams, Link } from 'react-router-dom'
import { useIncident } from '../hooks/useIncidents'
import SeverityBadge from '../components/SeverityBadge'
import MitreTacticBadge from '../components/MitreTacticBadge'
import ShapWaterfallChart from '../components/ShapWaterfallChart'

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: incident, isLoading, error } = useIncident(id ?? '')

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-slate-400">
        Loading incident…
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4 text-slate-400">
        <p>Incident not found.</p>
        <Link to="/" className="text-blue-400 hover:text-blue-300">← Back to Dashboard</Link>
      </div>
    )
  }

  const shapFeatures = incident.shap_values ?? []

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      {/* Back link */}
      <Link to="/" className="text-blue-400 hover:text-blue-300 text-sm mb-6 inline-block">
        ← Back to Dashboard
      </Link>

      {/* Header */}
      <div className="flex items-start gap-4 mb-6">
        <SeverityBadge severity={incident.severity} />
        <div>
          <h1 className="text-2xl font-bold text-slate-100">{incident.threat_label}</h1>
          <p className="text-slate-400 text-sm font-mono">{incident.id}</p>
          <p className="text-slate-500 text-xs mt-1">
            {new Date(incident.created_at).toLocaleString()}
          </p>
        </div>
        <a
          href={`/api/reports/${incident.id}`}
          target="_blank"
          rel="noreferrer"
          className="ml-auto bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded text-sm font-medium"
        >
          Download PDF Report
        </a>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: 'Confidence', value: `${(incident.confidence * 100).toFixed(1)}%` },
          { label: 'Anomaly Score', value: incident.anomaly_score.toFixed(4) },
          { label: 'Status', value: incident.status },
        ].map(({ label, value }) => (
          <div key={label} className="bg-slate-900 border border-slate-800 rounded p-4">
            <p className="text-slate-500 text-xs mb-1">{label}</p>
            <p className="text-slate-100 font-bold text-lg">{value}</p>
          </div>
        ))}
      </div>

      {/* IPs */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        {[
          { label: 'Source IP', value: incident.source_ip },
          { label: 'Destination IP', value: incident.dest_ip },
        ].map(({ label, value }) => (
          <div key={label} className="bg-slate-900 border border-slate-800 rounded p-4">
            <p className="text-slate-500 text-xs mb-1">{label}</p>
            <p className="text-slate-100 font-mono">{value ?? '—'}</p>
          </div>
        ))}
      </div>

      {/* MITRE ATT&CK */}
      {incident.mitre_techniques?.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded p-4 mb-6">
          <h2 className="text-sm font-semibold text-slate-300 mb-3">MITRE ATT&CK Techniques</h2>
          <div className="flex flex-wrap gap-2">
            {incident.mitre_techniques.map((ttp: any) => (
              <a
                key={ttp.technique_id}
                href={ttp.url}
                target="_blank"
                rel="noreferrer"
                title={ttp.technique_name}
              >
                <MitreTacticBadge tactic={ttp.tactic} techniqueId={ttp.technique_id} />
              </a>
            ))}
          </div>
        </div>
      )}

      {/* SHAP Explanation */}
      {shapFeatures.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded p-4 mb-6">
          <ShapWaterfallChart features={shapFeatures} />
        </div>
      )}
    </div>
  )
}
