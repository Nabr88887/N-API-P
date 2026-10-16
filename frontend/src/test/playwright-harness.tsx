import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { App, type Role } from '../App'
import type { EmployeePortalClient, KeyIssuance, PersonalKey, UsageRecord } from '../employee-api'
import type { TeamMember, TeamPortalClient, TeamUsageResponse } from '../team-api'
import type {
  Account,
  AdminPortalClient,
  AuditMetadata,
  HealthResponse,
  Key,
  Model,
  OperationalEvent,
  RawAuditView,
  RetentionPolicy,
  ServiceAccount,
  Team,
} from '../admin-api'

const now = '2026-08-14T09:00:00Z'
const roleParam = new URLSearchParams(window.location.search).get('role')
const role: Role = roleParam === 'employee' || roleParam === 'team_administrator' ? roleParam : 'system_administrator'
const fault = new URLSearchParams(window.location.search).get('fault')
const emptyTeams = new URLSearchParams(window.location.search).get('teams') === 'empty'

const personalKey: PersonalKey = {
  id: 'personal-key-1',
  kind: 'personal',
  owner_account_id: 'employee-1',
  name: 'workstation',
  prefix: 'nap_12345678',
  status: 'active',
  created_at: now,
}
const usage: UsageRecord = {
  id: 'usage-1',
  audit_id: 'audit-1',
  request_id: 'request-1',
  key_id: personalKey.id,
  owner_account_id: 'employee-1',
  team_id: 'team-1',
  model_id: 'gpt-internal-long-model-name-for-overflow-check',
  outcome: 'success',
  usage_reported: true,
  usage: { input_tokens: 1200, output_tokens: 800, total_tokens: 2000 },
  created_at: now,
}

function page<T>(data: T[]): { data: T[]; pagination: { has_more: false } } {
  return { data, pagination: { has_more: false } }
}

function employeeClient(): EmployeePortalClient {
  return {
    login: async () => undefined,
    listPersonalKeys: async () => page([personalKey]),
    createPersonalKey: async (name): Promise<KeyIssuance> => ({
      key: { ...personalKey, id: 'personal-key-2', name },
      credential: { value: 'nap_synthetic_one_time_value' },
    }),
    revokePersonalKey: async () => undefined,
    listUsage: async () => page([usage]),
  }
}

function teamClient(): TeamPortalClient {
  const member: TeamMember = { account_id: 'employee-1', email: 'employee@company.internal', role: 'employee', status: 'active', joined_at: now }
  const response: TeamUsageResponse = { ...page([usage]), aggregate: { request_count: 1, reported_usage_count: 1, input_tokens: 1200, output_tokens: 800, total_tokens: 2000 } }
  return {
    listTeamMembers: async () => page([member]),
    listTeamUsage: async () => response,
  }
}

function adminClient(): AdminPortalClient {
  let reauthenticated = false
  let failTeamCreate = fault === 'team_create_once'
  const account: Account = { id: 'employee-1', email: 'employee@company.internal', role: 'employee', status: 'active', team_ids: ['team-1'], created_at: now }
  const team: Team = { id: 'team-1', name: 'Platform', status: 'active', member_count: 1, created_at: now }
  const teams: Team[] = emptyTeams ? [] : [team]
  const service: ServiceAccount = { id: 'service-1', team_id: team.id, responsible_account_id: account.id, name: 'ci-agent', status: 'active', created_at: now }
  const key: Key = { id: 'service-key-1', kind: 'service', service_account_id: service.id, team_id: team.id, name: 'deploy', prefix: 'nap_87654321', status: 'active', created_at: now }
  const serviceKeys = Array.from({ length: 50 }, (_, index) => ({
    ...key,
    id: `service-key-${index + 1}`,
    name: index === 0 ? key.name : `deploy-${index + 1}`,
    prefix: `nap_${String(index + 87654321).slice(-8)}`,
  }))
  const model: Model = { id: 'gpt-internal', status: 'allowed', price_version: '2026-01', updated_at: now }
  const audit: AuditMetadata = { id: 'audit-1', request_id: 'request-1', key_id: personalKey.id, owner_account_id: account.id, team_id: team.id, model_id: model.id, capture_status: 'complete', outcome: 'success', observed_request_bytes: 512, observed_response_bytes: 1024, created_at: now, updated_at: now }
  const event: OperationalEvent = { id: 'event-1', event_type: 'audit_unavailable', severity: 'critical', occurred_at: now }
  const health: HealthResponse = fault === 'audit_unavailable'
    ? { state: 'unhealthy', components: [{ name: 'audit_unavailable', state: 'unhealthy', detail_code: 'audit_unavailable', checked_at: now }], checked_at: now }
    : { state: 'healthy', components: [], checked_at: now }
  const retention: RetentionPolicy = { days: 7, maximum_days: 30, updated_at: now }
  const rawView: RawAuditView = { audit_id: audit.id, request: { messages: [{ role: 'user', content: 'synthetic request text' }] }, response: { choices: [{ message: { content: 'synthetic response text' } }] } }
  return {
    listAccounts: async () => page([account]),
    listTeams: async () => page([...teams]),
    createTeam: async (name) => {
      if (failTeamCreate) {
        failTeamCreate = false
        throw new Error('synthetic team creation failure')
      }
      const created: Team = { id: `team-created-${teams.length + 1}`, name, status: 'active', member_count: 0, created_at: now }
      teams.push(created)
      return created
    },
    disableTeam: async () => undefined,
    invite: async (email, teamID) => ({ invitation: { account_id: 'employee-2', email, team_id: teamID, status: 'pending', expires_at: now, created_at: now }, activation_code: 'synthetic-activation-code' }),
    updateAccount: async () => undefined,
    addMember: async () => undefined,
    removeMember: async () => undefined,
    listServiceAccounts: async () => page([service]),
    createServiceAccount: async (teamID, responsibleAccountID, name) => ({ ...service, id: 'service-2', team_id: teamID, responsible_account_id: responsibleAccountID, name }),
    disableServiceAccount: async () => undefined,
    listServiceKeys: async () => page(serviceKeys),
    createServiceKey: async (serviceAccountID, name) => ({ key: { ...key, id: 'service-key-51', service_account_id: serviceAccountID, name }, credential: { value: 'nap_synthetic_group_value' } }),
    rotateServiceKey: async (serviceAccountID, _keyID, name) => ({ key: { ...key, id: 'service-key-52', service_account_id: serviceAccountID, name }, credential: { value: 'nap_synthetic_rotated_value' } }),
    revokeServiceKey: async () => undefined,
    getModelAllowlist: async () => page([model]),
    replaceModelAllowlist: async (models) => {
      if (!reauthenticated) throw { code: 'REAUTHENTICATION_REQUIRED' }
      return page(models)
    },
    getRetentionPolicy: async () => retention,
    replaceRetentionPolicy: async (days) => ({ ...retention, days }),
    issuePasswordReset: async (accountID, email) => ({ code: `synthetic-reset-${accountID}`, email, expires_at: now }),
    listAudits: async () => page([audit]),
    inspectAudit: async () => rawView,
    getOperationsHealth: async () => health,
    listOperationalEvents: async () => page([event]),
    listSecurityEvents: async () => page([]),
    reauthenticate: async () => { reauthenticated = true },
  }
}

const root = document.getElementById('root')
if (!root) throw new Error('test harness root is missing')

createRoot(root).render(
  <StrictMode>
    <App role={role} employeeClient={employeeClient()} teamClient={teamClient()} adminClient={adminClient()} teamID="team-1" />
  </StrictMode>,
)
