import { useCallback, useMemo, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Incident, useIncidentStore } from '../store/incidents'
import { IncidentSummarySchema } from '../schemas/incident'
import { useWebSocket } from '../hooks/useWebSocket'
import { useAuthStore } from '../store/auth'
import SeverityBadge from './SeverityBadge'

const SEVERITY_ROW: Record<string, string> = {
  CRITICAL: 'border-l-red-500 bg-red-950/25',
  HIGH: 'border-l-orange-500 bg-orange-950/20',
  MEDIUM: 'border-l-yellow-500 bg-yellow-950/10',
  LOW: 'border-l-blue-500 bg-blue-950/10',
  INFO: 'border-l-green-500 bg-transparent',
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  return new Date(iso).toLocaleTimeString()
}

function resolveWsUrl(token: string | null): string {
  // Prefer the same-origin approach so nginx can terminate wss:// and forward
  // the upgraded socket to the API. VITE_WS_URL only overrides when the
  // dashboard is hosted separately from the reverse proxy.
  const override = import.meta.env.VITE_WS_URL as string | undefined
  const base =
    override ??
    `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`

  const url = new URL('/ws/feed', base)
  if (token) url.searchParams.set('token', token)
  return url.toString()
}

function IncidentRow({ incident }: { incident: Incident }) {
  const rowColors = SEVERITY_ROW[incident.severity] ?? 'border-l-slate-600 bg-transparent'
  return (
    <div className={`animate-slide-in flex items-center gap-3 pl-3 pr-4 py-2.5 border-b border-slate-800/60 border-l-[3px] hover:brightness-125 transition-all text-xs ${rowColors}`}>
      <span className="text-slate-500 w-16 shrink-0 tabular-nums">{relativeTime(incident.created_at)}</span>
      <SeverityBadge severity={incident.severity} size="sm" />
      <span className="font-semibold text-slate-100 w-24 shrink-0 truncate">{incident.threat_label}</span>
      <span className="text-slate-500 truncate flex-1 font-mono text-[10px]">
        {incident.source_ip ?? '—'} → {incident.dest_ip ?? '—'}
      </span>
      <span className="text-slate-400 tabular-nums ml-auto shrink-0">
        {(incident.confidence * 100).toFixed(0)}%
      </span>
    </div>
  )
}

export default function ThreatFeed() {
  const { incidents, addIncident } = useIncidentStore()
  const token = useAuthStore((s) => s.token)
  const parentRef = useRef<HTMLDivElement>(null)

  const wsUrl = useMemo(() => resolveWsUrl(token), [token])

  const onMessage = useCallback(
    (data: unknown) => {
      const parsed = IncidentSummarySchema.safeParse(data)
      if (parsed.success) addIncident(parsed.data as Incident)
    },
    [addIncident],
  )

  useWebSocket(wsUrl, onMessage, !!token)

  const rowVirtualizer = useVirtualizer({
    count: incidents.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 42,
    overscan: 10,
  })

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700/60">
        <div className="flex items-center gap-2">
          <span className="text-blue-400" aria-hidden="true">⚡</span>
          <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Live Threat Feed</h2>
        </div>
        <span className="text-[10px] text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
          {incidents.length} events
        </span>
      </div>

      <div ref={parentRef} className="flex-1 overflow-auto">
        {incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-600">
            <span className="text-4xl" aria-hidden="true">🛡️</span>
            <p className="text-xs text-center leading-relaxed">
              No events yet<br />
              <span className="text-slate-700">Predictions appear here in real time</span>
            </p>
          </div>
        ) : (
          <div style={{ height: rowVirtualizer.getTotalSize(), position: 'relative' }}>
            {rowVirtualizer.getVirtualItems().map((virtualRow) => (
              <div
                key={virtualRow.index}
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  transform: `translateY(${virtualRow.start}px)`,
                }}
              >
                <IncidentRow incident={incidents[virtualRow.index]} />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
