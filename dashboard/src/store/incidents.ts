import { create } from 'zustand'

export interface Incident {
  id: string
  created_at: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  threat_label: string
  confidence: number
  anomaly_score: number
  source_ip: string | null
  dest_ip: string | null
  status: string
  mitre_techniques: Array<{
    technique_id: string
    technique_name: string
    tactic: string
  }>
}

interface IncidentStore {
  incidents: Incident[]
  addIncident: (incident: Incident) => void
  clearIncidents: () => void
}

export const useIncidentStore = create<IncidentStore>((set) => ({
  incidents: [],
  addIncident: (incident) =>
    set((state) => ({
      // Keep max 500 incidents in memory — oldest drop off
      incidents: [incident, ...state.incidents].slice(0, 500),
    })),
  clearIncidents: () => set({ incidents: [] }),
}))
