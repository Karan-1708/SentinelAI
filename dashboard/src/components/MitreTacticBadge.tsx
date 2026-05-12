const TACTIC_COLORS: Record<string, string> = {
  'initial-access': 'bg-red-900 text-red-200',
  'execution': 'bg-orange-900 text-orange-200',
  'persistence': 'bg-yellow-900 text-yellow-200',
  'privilege-escalation': 'bg-amber-900 text-amber-200',
  'defense-evasion': 'bg-lime-900 text-lime-200',
  'credential-access': 'bg-green-900 text-green-200',
  'discovery': 'bg-teal-900 text-teal-200',
  'lateral-movement': 'bg-cyan-900 text-cyan-200',
  'collection': 'bg-blue-900 text-blue-200',
  'command-and-control': 'bg-indigo-900 text-indigo-200',
  'exfiltration': 'bg-violet-900 text-violet-200',
  'impact': 'bg-purple-900 text-purple-200',
  'reconnaissance': 'bg-fuchsia-900 text-fuchsia-200',
  'resource-development': 'bg-pink-900 text-pink-200',
  'unknown': 'bg-slate-700 text-slate-300',
}

interface Props {
  tactic: string
  techniqueId?: string
}

export default function MitreTacticBadge({ tactic, techniqueId }: Props) {
  const colorClass = TACTIC_COLORS[tactic.toLowerCase()] ?? TACTIC_COLORS['unknown']
  const label = tactic.replace(/-/g, ' ')
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${colorClass}`}>
      {techniqueId && <span className="opacity-70">{techniqueId}</span>}
      <span>{label}</span>
    </span>
  )
}
