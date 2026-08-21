import { currentCSRFToken, rememberCSRFToken } from './portal-session'

export type PortalRole = 'employee' | 'team_administrator' | 'system_administrator'

export type PortalIdentity = {
  id: string
  email: string
  role: PortalRole
  team_ids?: string[]
}

export interface PortalClient {
  me(): Promise<PortalIdentity>
  login(email: string, password: string): Promise<void>
  activate(email: string, activationCode: string, password: string): Promise<void>
  resetPassword(email: string, code: string, password: string): Promise<void>
  logout(): Promise<void>
}

export class PortalAPIError extends Error {
  constructor(public readonly code: string) {
    super(code)
  }
}

export function createPortalClient(): PortalClient {
  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers)
    if (init.body !== undefined) headers.set('Content-Type', 'application/json')
    if (init.method && init.method !== 'GET') {
      const csrfToken = currentCSRFToken()
      if (csrfToken) headers.set('X-CSRF-Token', csrfToken)
    }
    const response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
    rememberCSRFToken(response.headers.get('X-CSRF-Token'))
    if (!response.ok) {
      let code = 'INTERNAL_ERROR'
      try {
        code = (await response.json() as { error?: { code?: string } }).error?.code ?? code
      } catch {
        // Keep the public fallback independent of transport details.
      }
      throw new PortalAPIError(code)
    }
    if (response.status === 204) return undefined as T
    return response.json() as Promise<T>
  }

  return {
    me: () => request<PortalIdentity>('/api/v1/me'),
    login: (email, password) => request<void>('/api/v1/sessions', { method: 'POST', body: JSON.stringify({ email, password }) }),
    activate: (email, activationCode, password) => request<void>('/api/v1/activations', { method: 'POST', body: JSON.stringify({ email, activation_code: activationCode, password }) }),
    resetPassword: (email, code, password) => request<void>('/api/v1/password-reset-completions', { method: 'POST', body: JSON.stringify({ email, code, new_password: password }) }),
    logout: () => request<void>('/api/v1/sessions/current', { method: 'DELETE' }),
  }
}
