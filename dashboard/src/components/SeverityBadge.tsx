const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-black',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-green-600 text-white',
}

interface Props {
  severity: string
  size?: 'sm' | 'md'
}

export default function SeverityBadge({ severity, size = 'md' }: Props) {
  const colorClass = SEVERITY_STYLES[severity] ?? 'bg-slate-600 text-white'
  const sizeClass = size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2.5 py-1 text-sm'
  return (
    <span className={`inline-block rounded font-bold uppercase tracking-wide ${colorClass} ${sizeClass}`}>
      {severity}
    </span>
  )
}
