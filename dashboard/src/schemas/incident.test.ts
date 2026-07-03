import { describe, expect, it } from 'vitest'
import {
  IncidentSummarySchema,
  MitreTechniqueSchema,
  safeHttpUrl,
} from './incident'

describe('IncidentSummarySchema', () => {
  it('accepts a well-formed payload', () => {
    const parsed = IncidentSummarySchema.parse({
      id: '11111111-2222-3333-4444-555555555555',
      created_at: '2026-07-02T00:00:00Z',
      severity: 'HIGH',
      threat_label: 'DDoS',
      confidence: 0.93,
      anomaly_score: -0.21,
      source_ip: '203.0.113.1',
      dest_ip: '10.0.0.5',
      status: 'OPEN',
      mitre_techniques: [],
    })
    expect(parsed.severity).toBe('HIGH')
  })

  it('rejects an unknown severity', () => {
    expect(() =>
      IncidentSummarySchema.parse({
        id: '11111111-2222-3333-4444-555555555555',
        created_at: '2026-07-02T00:00:00Z',
        severity: 'DISASTER',
        threat_label: 'DDoS',
        confidence: 0.93,
        anomaly_score: -0.21,
        status: 'OPEN',
      }),
    ).toThrow()
  })

  it('rejects a non-UUID id', () => {
    expect(() =>
      IncidentSummarySchema.parse({
        id: 'not-a-uuid',
        created_at: '2026-07-02T00:00:00Z',
        severity: 'HIGH',
        threat_label: 'DDoS',
        confidence: 0.93,
        anomaly_score: -0.21,
        status: 'OPEN',
      }),
    ).toThrow()
  })
})

describe('MitreTechniqueSchema.url', () => {
  it('accepts https URLs', () => {
    const ttp = MitreTechniqueSchema.parse({
      technique_id: 'T1498',
      technique_name: 'Network DoS',
      tactic: 'impact',
      url: 'https://attack.mitre.org/techniques/T1498/',
    })
    expect(ttp.url).toBe('https://attack.mitre.org/techniques/T1498/')
  })
})

describe('safeHttpUrl', () => {
  it('returns null for javascript: scheme', () => {
    expect(safeHttpUrl('javascript:alert(1)')).toBeNull()
  })

  it('returns null for data: scheme', () => {
    expect(safeHttpUrl('data:text/html,<script>alert(1)</script>')).toBeNull()
  })

  it('returns null for malformed strings', () => {
    expect(safeHttpUrl('not a url')).toBeNull()
    expect(safeHttpUrl(undefined)).toBeNull()
    expect(safeHttpUrl('')).toBeNull()
  })

  it('normalises and returns https URLs', () => {
    expect(safeHttpUrl('https://attack.mitre.org/techniques/T1498/')).toBe(
      'https://attack.mitre.org/techniques/T1498/',
    )
  })

  it('accepts http URLs (nginx will still redirect)', () => {
    expect(safeHttpUrl('http://example.com/x')).toBe('http://example.com/x')
  })
})
