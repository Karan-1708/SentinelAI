import { useQuery } from '@tanstack/react-query'
import { apiClient } from '../api/client'
import {
  IncidentDetailSchema,
  IncidentListResponseSchema,
} from '../schemas/incident'

interface IncidentListParams {
  page?: number
  page_size?: number
  severity?: string
  status?: string
}

export function useIncidents(params: IncidentListParams = {}) {
  return useQuery({
    queryKey: ['incidents', params],
    queryFn: async () => {
      const searchParams = new URLSearchParams()
      if (params.page) searchParams.set('page', String(params.page))
      if (params.page_size) searchParams.set('page_size', String(params.page_size))
      if (params.severity) searchParams.set('severity', params.severity)
      if (params.status) searchParams.set('status', params.status)

      const { data } = await apiClient.get(`/incidents?${searchParams.toString()}`)
      return IncidentListResponseSchema.parse(data)
    },
    refetchInterval: 30_000,
  })
}

export function useIncident(id: string) {
  return useQuery({
    queryKey: ['incident', id],
    queryFn: async () => {
      const { data } = await apiClient.get(`/incidents/${id}`)
      return IncidentDetailSchema.parse(data)
    },
    enabled: !!id,
  })
}
