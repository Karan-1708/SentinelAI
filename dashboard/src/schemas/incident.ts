import { z } from 'zod'

/**
 * Runtime validation of every payload that enters the dashboard.
 * The backend is trusted, but "server data is safe" is not a security
 * argument — a bug or a compromised upstream would otherwise flow straight
 * into JSX.
 */

export const SeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
export const StatusSchema = z.enum(['OPEN', 'IN_PROGRESS', 'CLOSED'])

export const MitreTechniqueSchema = z.object({
  technique_id: z.string().max(32),
  technique_name: z.string().max(200),
  tactic: z.string().max(64),
  url: z.string().url().optional(),
})

export const ShapContributionSchema = z.object({
  feature: z.string().max(128),
  shap_value: z.number(),
  feature_value: z.number().optional(),
})

export const IncidentSummarySchema = z.object({
  id: z.string().uuid(),
  created_at: z.string(),
  severity: SeveritySchema,
  threat_label: z.string().max(64),
  confidence: z.number(),
  anomaly_score: z.number(),
  source_ip: z.string().nullable().optional(),
  dest_ip: z.string().nullable().optional(),
  status: StatusSchema.or(z.string()),
  mitre_techniques: z.array(MitreTechniqueSchema).default([]),
})

export const IncidentDetailSchema = IncidentSummarySchema.extend({
  shap_values: z.array(ShapContributionSchema).nullable().optional(),
  raw_features: z.record(z.string(), z.number()).default({}),
})

export const IncidentListResponseSchema = z.object({
  items: z.array(IncidentSummarySchema),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  page_size: z.number().int().positive(),
})

export type IncidentSummary = z.infer<typeof IncidentSummarySchema>
export type IncidentDetail = z.infer<typeof IncidentDetailSchema>
export type IncidentListResponse = z.infer<typeof IncidentListResponseSchema>
export type MitreTechnique = z.infer<typeof MitreTechniqueSchema>

/**
 * Guard against `javascript:` and other non-http(s) schemes in MITRE URLs
 * before rendering them as `<a href>`.
 */
export function safeHttpUrl(candidate: unknown): string | null {
  if (typeof candidate !== 'string' || candidate.length === 0) return null
  try {
    const url = new URL(candidate)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
    return url.toString()
  } catch {
    return null
  }
}
