import { currentCSRFToken, rememberCSRFToken } from './portal-session'

export type Role = 'employee' | 'team_administrator' | 'system_administrator'
export type AccountStatus = 'pending' | 'active' | 'disabled'
export type TeamStatus = 'active' | 'disabled'
export type ServiceAccountStatus = 'active' | 'disabled'
export type KeyStatus = 'active' | 'revoked'
export type ModelStatus = 'allowed' | 'disabled'
export type AuditCaptureStatus = 'pending' | 'complete' | 'truncated' | 'incomplete'
export type AuditOutcome = 'pending' | 'success' | 'upstream_error' | 'cancelled' | 'local_error'
export type HealthState = 'healthy' | 'degraded' | 'unhealthy'

export type Pagination = { next_cursor?: string; has_more: boolean }
export type PagedResponse<T> = { data: T[]; pagination: Pagination }
export type Account = { id: string; email: string; role: Role; status: AccountStatus; team_ids?: string[]; created_at: string; updated_at?: string; disabled_at?: string }
export type Team = { id: string; name: string; status: TeamStatus; member_count: number; created_at: string; updated_at?: string; disabled_at?: string }
export type ServiceAccount = { id: string; team_id: string; responsible_account_id: string; name: string; status: ServiceAccountStatus; created_at: string; updated_at?: string; disabled_at?: string }
export type Key = { id: string; kind: 'service'; service_account_id: string; team_id: string; name: string; prefix: string; status: KeyStatus; created_at: string; last_used_at?: string; revoked_at?: string }
export type KeyIssuance = { key: Key; credential: { value: string } }
export type Model = { id: string; status: ModelStatus; input_unit_price?: string; output_unit_price?: string; price_version?: string; updated_at: string }
export type RetentionPolicy = { days: number; maximum_days: number; updated_at: string }
export type InvitationIssuance = { invitation: { account_id: string; email: string; team_id: string; status: AccountStatus; expires_at: string; created_at: string }; activation_code: string }
export type PasswordResetIssuance = { code: string; email: string; expires_at: string }
export type AuditMetadata = { id: string; request_id: string; key_id: string; owner_account_id?: string; service_account_id?: string; responsible_account_id?: string; team_id: string; model_id: string; capture_status: AuditCaptureStatus; outcome: AuditOutcome; upstream_request_id?: string; upstream_http_status?: number; error_code?: string; finish_reason?: string; observed_request_bytes: number; observed_response_bytes: number; created_at: string; updated_at: string; completed_at?: string }
export type RawAuditView = { audit_id: string; request: unknown; response: unknown }
export type HealthComponent = { name: string; state: HealthState; detail_code?: string; checked_at: string }
export type HealthResponse = { state: HealthState; components: HealthComponent[]; checked_at: string }
export type OperationalEvent = { id: string; event_type: string; severity: string; detail_code?: string; occurred_at: string }

export class AdminAPIError extends Error {
  constructor(public readonly code: string) { super(code) }
}

export interface AdminPortalClient {
  listAccounts(query?: { cursor?: string; status?: AccountStatus; role?: Role }): Promise<PagedResponse<Account>>
  listTeams(query?: { cursor?: string; status?: TeamStatus }): Promise<PagedResponse<Team>>
  disableTeam(teamID: string): Promise<void>
  invite(email: string, teamID: string): Promise<InvitationIssuance>
  updateAccount(accountID: string, input: { role?: Role; status?: AccountStatus; confirmed?: boolean }): Promise<void>
  addMember(teamID: string, accountID: string): Promise<void>
  removeMember(teamID: string, accountID: string): Promise<void>
  listServiceAccounts(query?: { cursor?: string; team_id?: string; status?: ServiceAccountStatus }): Promise<PagedResponse<ServiceAccount>>
  createServiceAccount(teamID: string, responsibleAccountID: string, name: string): Promise<ServiceAccount>
  disableServiceAccount(serviceAccountID: string): Promise<void>
  listServiceKeys(serviceAccountID: string): Promise<PagedResponse<Key>>
  createServiceKey(serviceAccountID: string, name: string): Promise<KeyIssuance>
  rotateServiceKey(serviceAccountID: string, keyID: string, name: string): Promise<KeyIssuance>
  revokeServiceKey(serviceAccountID: string, keyID: string): Promise<void>
  getModelAllowlist(): Promise<PagedResponse<Model>>
  replaceModelAllowlist(models: Model[], confirmed: boolean): Promise<PagedResponse<Model>>
  getRetentionPolicy(): Promise<RetentionPolicy>
  replaceRetentionPolicy(days: number, confirmed: boolean): Promise<RetentionPolicy>
  issuePasswordReset(accountID: string, email: string, manualIdentityVerified: boolean, compromiseResponse: boolean): Promise<PasswordResetIssuance>
  listAudits(query?: { cursor?: string; account_id?: string; team_id?: string; model_id?: string; capture_status?: AuditCaptureStatus }): Promise<PagedResponse<AuditMetadata>>
  inspectAudit(auditID: string, reason: string): Promise<RawAuditView>
  getOperationsHealth(): Promise<HealthResponse>
  listOperationalEvents(query?: { cursor?: string }): Promise<PagedResponse<OperationalEvent>>
  reauthenticate(password: string): Promise<void>
}

export function createAdminPortalClient(): AdminPortalClient {
  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers)
    if (init.body !== undefined) headers.set('Content-Type', 'application/json')
	const csrfToken = currentCSRFToken()
	if (init.method && init.method !== 'GET' && csrfToken) headers.set('X-CSRF-Token', csrfToken)
    const response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
	rememberCSRFToken(response.headers.get('X-CSRF-Token'))
    if (!response.ok) {
      let code = 'INTERNAL_ERROR'
      try { code = (await response.json() as { error?: { code?: string } }).error?.code ?? code } catch { /* stable transport fallback */ }
      throw new AdminAPIError(code)
    }
    if (response.status === 204) return undefined as T
    return response.json() as Promise<T>
  }
  function pagePath(path: string, query: Record<string, string | undefined> = {}) {
    const params = new URLSearchParams({ limit: '50' })
    Object.entries(query).forEach(([key, value]) => { if (value) params.set(key, value) })
    return `${path}?${params.toString()}`
  }
  return {
    listAccounts: (query = {}) => request(pagePath('/api/v1/users', query)),
    listTeams: (query = {}) => request(pagePath('/api/v1/teams', query)),
    disableTeam: (id) => request(`/api/v1/teams/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ confirmed: true }) }),
    invite: (email, teamID) => request('/api/v1/invitations', { method: 'POST', body: JSON.stringify({ email, team_id: teamID }) }),
    updateAccount: (id, input) => request(`/api/v1/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(input) }),
    addMember: (teamID, accountID) => request(`/api/v1/teams/${encodeURIComponent(teamID)}/members/${encodeURIComponent(accountID)}`, { method: 'PUT', body: '{}' }),
    removeMember: (teamID, accountID) => request(`/api/v1/teams/${encodeURIComponent(teamID)}/members/${encodeURIComponent(accountID)}`, { method: 'DELETE', body: JSON.stringify({ confirmed: true }) }),
    listServiceAccounts: (query = {}) => request(pagePath('/api/v1/service-accounts', query)),
    createServiceAccount: (teamID, responsibleAccountID, name) => request('/api/v1/service-accounts', { method: 'POST', body: JSON.stringify({ team_id: teamID, responsible_account_id: responsibleAccountID, name }) }),
    disableServiceAccount: (id) => request(`/api/v1/service-accounts/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ status: 'disabled', confirmed: true }) }),
    listServiceKeys: (id) => request(pagePath(`/api/v1/service-accounts/${encodeURIComponent(id)}/keys`)),
    createServiceKey: (id, name) => request(`/api/v1/service-accounts/${encodeURIComponent(id)}/keys`, { method: 'POST', body: JSON.stringify({ name }) }),
    rotateServiceKey: (id, keyID, name) => request(`/api/v1/service-accounts/${encodeURIComponent(id)}/keys/${encodeURIComponent(keyID)}/rotations`, { method: 'POST', body: JSON.stringify({ name, confirmed: true }) }),
    revokeServiceKey: (id, keyID) => request(`/api/v1/service-accounts/${encodeURIComponent(id)}/keys/${encodeURIComponent(keyID)}`, { method: 'DELETE', body: JSON.stringify({ confirmed: true }) }),
    getModelAllowlist: () => request('/api/v1/model-allowlist'),
    replaceModelAllowlist: (models, confirmed) => request('/api/v1/model-allowlist', { method: 'PUT', body: JSON.stringify({ models, confirmed }) }),
    getRetentionPolicy: () => request('/api/v1/retention-policy'),
    replaceRetentionPolicy: (days, confirmed) => request('/api/v1/retention-policy', { method: 'PUT', body: JSON.stringify({ days, confirmed }) }),
    issuePasswordReset: (id, email, manualIdentityVerified, compromiseResponse) => request(`/api/v1/users/${encodeURIComponent(id)}/password-reset-codes`, { method: 'POST', body: JSON.stringify({ email, manual_identity_verified: manualIdentityVerified, compromise_response: compromiseResponse }) }),
    listAudits: (query = {}) => request(pagePath('/api/v1/audits', query)),
    inspectAudit: (id, reason) => request(`/api/v1/audits/${encodeURIComponent(id)}/raw-views`, { method: 'POST', body: JSON.stringify({ reason }) }),
    getOperationsHealth: () => request('/api/v1/operations/health'),
    listOperationalEvents: (query = {}) => request(pagePath('/api/v1/operations/events', query)),
    reauthenticate: (password) => request('/api/v1/sessions/current/reauthentications', { method: 'POST', body: JSON.stringify({ password }) }),
  }
}
