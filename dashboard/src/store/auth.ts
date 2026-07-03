import { create } from 'zustand'

/**
 * The access token is held in memory only. We deliberately do not use
 * localStorage: an XSS on this app would immediately exfiltrate a long-lived
 * token. Tabs re-authenticate on refresh; the trade-off is an extra login
 * round trip for a much smaller blast radius on token theft.
 */
interface AuthState {
  token: string | null
  expiresAt: number | null
  setToken: (token: string, expiresIn: number) => void
  clear: () => void
  isAuthed: () => boolean
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: null,
  expiresAt: null,
  setToken: (token, expiresIn) =>
    set({ token, expiresAt: Date.now() + expiresIn * 1000 }),
  clear: () => set({ token: null, expiresAt: null }),
  isAuthed: () => {
    const { token, expiresAt } = get()
    return !!token && !!expiresAt && Date.now() < expiresAt
  },
}))
