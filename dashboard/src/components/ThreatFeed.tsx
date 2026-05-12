import { useCallback } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef } from 'react'
import { Incident, useIncidentStore } from '../store/incidents'
import { useWebSocket } from '../hooks/useWebSocket'
import SeverityBadge from './SeverityBadge'

const WS_URL = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000') + '/ws/feed'

function IncidentRow({ incident }: { incident: Incident }) {
  const time = new Date(incident.created_at).toLocaleTimeString()
  return (
    <div className="flex items-center gap-3 px-3 py-2 border-b border-slate-800 hover:bg-slate-900 text-sm">
      <span className="text-slate-400 text-xs w-20 shrink-0">{time}</span>
      <SeverityBadge severity={incident.severity} size="sm" />
      <span className="font-semibold text-slate-200 w-28 shrink-0 truncate">
        {incident.threat_label}
      </span>
      <span className="text-slate-400 text-xs truncate">
        {incident.source_ip ?? '—'} → {incident.dest_ip ?? '—'}
      </span>
      <span className="ml-auto text-slate-500 text-xs">
        {(incident.confidence * 100).toFixed(0)}%
      </span>
    </div>
  )
}

export default function ThreatFeed() {
  const { incidents, addIncident } = useIncidentStore()
  const parentRef = useRef<HTMLDivElement>(null)

  const onMessage = useCallback(
    (data: unknown) => {
      if (data && typeof data === 'object') {
        addIncident(data as Incident)
      }
    },
    [addIncident],
  )

  useWebSocket(WS_URL, onMessage)

  const rowVirtualizer = useVirtualizer({
    count: incidents.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 44,
    overscan: 10,
  })

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-700">
        <h2 className="text-sm font-semibold text-slate-300">Live Threat Feed</h2>
        <span className="text-xs text-slate-500">{incidents.length} events</span>
      </div>
      <div ref={parentRef} className="flex-1 overflow-auto">
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
        {incidents.length === 0 && (
          <div className="flex items-center justify-center h-32 text-slate-500 text-sm">
            Waiting for events…
          </div>
        )}
      </div>
    </div>
  )
}
