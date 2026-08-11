export type Pagination = {
  next_cursor?: string
  has_more: boolean
}

export type PagedResponse<T> = {
  data: T[]
  pagination: Pagination
}

export type PersonalKey = {
  id: string
  kind: 'personal'
  owner_account_id: string
  name: string
  prefix: string
  status: 'active' | 'revoked'
  created_at: string
  last_used_at?: string
  revoked_at?: string
}

export type KeyIssuance = {
  key: PersonalKey
  credential: { value: string }
}

export type UsageRecord = {
  id: string
  audit_id: string
  request_id: string
  key_id: string
  owner_account_id: string
  service_account_id?: string
  team_id: string
  model_id: string
  outcome: 'success' | 'upstream_error' | 'cancelled' | 'local_error'
  usage_reported: boolean
  usage?: { input_tokens: number; output_tokens: number; total_tokens: number }
  price_version?: string
  calculated_amount?: string
  created_at: string
}

export interface EmployeePortalClient {
  login(email: string, password: string): Promise<void>
  listPersonalKeys(cursor?: string): Promise<PagedResponse<PersonalKey>>
  createPersonalKey(name: string): Promise<KeyIssuance>
  revokePersonalKey(keyID: string): Promise<void>
  listUsage(cursor?: string): Promise<PagedResponse<UsageRecord>>
}

export class PortalAPIError extends Error {
  constructor(public readonly code: string) {
    super(code)
  }
}

export function createEmployeePortalClient(): EmployeePortalClient {
  let csrfToken = ''

  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers)
    if (init.body !== undefined) headers.set('Content-Type', 'application/json')
    if (init.method && init.method !== 'GET' && csrfToken) headers.set('X-CSRF-Token', csrfToken)
    const response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
    const rotatedCSRF = response.headers.get('X-CSRF-Token')
    if (rotatedCSRF) csrfToken = rotatedCSRF
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

  function pagePath(path: string, cursor?: string): string {
    if (!cursor) return `${path}?limit=50`
    return `${path}?limit=50&cursor=${encodeURIComponent(cursor)}`
  }

  return {
    async login(email, password) {
      await request<void>('/api/v1/sessions', { method: 'POST', body: JSON.stringify({ email, password }) })
    },
    listPersonalKeys(cursor) {
      return request<PagedResponse<PersonalKey>>(pagePath('/api/v1/me/personal-keys', cursor))
    },
    createPersonalKey(name) {
      return request<KeyIssuance>('/api/v1/me/personal-keys', { method: 'POST', body: JSON.stringify({ name }) })
    },
    revokePersonalKey(keyID) {
      return request<void>(`/api/v1/me/personal-keys/${encodeURIComponent(keyID)}`, { method: 'DELETE' })
    },
    listUsage(cursor) {
      return request<PagedResponse<UsageRecord>>(pagePath('/api/v1/me/usage', cursor))
    },
  }
}
