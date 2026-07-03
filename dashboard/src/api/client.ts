import axios from 'axios'
import { useAuthStore } from '../store/auth'

const rawBaseUrl = import.meta.env.VITE_API_BASE_URL || '/api'

if (import.meta.env.PROD && !import.meta.env.VITE_API_BASE_URL) {
  // Loud in prod, quiet in dev. A relative path is fine behind nginx, but the
  // absence of the env var means someone forgot to configure it.
  // eslint-disable-next-line no-console
  console.warn('VITE_API_BASE_URL is not set; falling back to /api (relative).')
}

export const apiClient = axios.create({
  baseURL: rawBaseUrl,
  timeout: 10_000,
  headers: {
    'Content-Type': 'application/json',
  },
})

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Session gone / expired. Clear the token; the app router will bounce
      // to /login on the next protected render.
      useAuthStore.getState().clear()
    }
    if (import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.error('API error:', error.response?.status, error.message)
    }
    return Promise.reject(error)
  },
)
