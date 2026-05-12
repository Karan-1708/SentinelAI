const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 ring-1 ring-red-500 text-red-400 shadow-[0_0_8px_rgba(239,68,68,0.35)]',
  HIGH:     'bg-orange-500/20 ring-1 ring-orange-500 text-orange-400',
  MEDIUM:   'bg-yellow-500/20 ring-1 ring-yellow-500 text-yellow-400',
  LOW:      'bg-blue-500/20 ring-1 ring-blue-500 text-blue-400',
  INFO:     'bg-green-500/20 ring-1 ring-green-500 text-green-400',
}

interface Props {
  severity: string
  size?: 'sm' | 'md' | 'lg'
}

export default function SeverityBadge({ severity, size = 'md' }: Props) {
  const colorClass = SEVERITY_STYLES[severity] ?? 'bg-slate-500/20 ring-1 ring-slate-500 text-slate-400'
  const sizeClass =
    size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' :
    size === 'lg' ? 'px-3 py-1.5 text-sm' :
    'px-2 py-0.5 text-xs'
  return (
    <span className={`inline-block rounded font-bold uppercase tracking-widest ${colorClass} ${sizeClass}`}>
      {severity}
    </span>
  )
}
