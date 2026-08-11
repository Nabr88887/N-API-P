import { PortalAPIError, type PagedResponse, type UsageRecord } from './employee-api'

export type TeamMember = {
  account_id: string
  email: string
  role: 'employee' | 'team_administrator' | 'system_administrator'
  status: 'pending' | 'active' | 'disabled'
  joined_at: string
}

export type TeamUsageAggregate = {
  request_count: number
  reported_usage_count: number
  input_tokens: number
  output_tokens: number
  total_tokens: number
}

export type TeamUsageResponse = PagedResponse<UsageRecord> & {
  aggregate: TeamUsageAggregate
}

export interface TeamPortalClient {
  listTeamMembers(teamID: string, cursor?: string): Promise<PagedResponse<TeamMember>>
  listTeamUsage(teamID: string, cursor?: string, accountID?: string): Promise<TeamUsageResponse>
}

export function createTeamPortalClient(): TeamPortalClient {
  async function request<T>(path: string): Promise<T> {
    const response = await fetch(path, { credentials: 'same-origin' })
    if (!response.ok) {
      let code = 'INTERNAL_ERROR'
      try {
        code = (await response.json() as { error?: { code?: string } }).error?.code ?? code
      } catch {
        // Keep the public fallback independent of transport details.
      }
      throw new PortalAPIError(code)
    }
    return response.json() as Promise<T>
  }

  function pagePath(teamID: string, resource: 'members' | 'usage', cursor?: string, accountID?: string): string {
    const base = `/api/v1/teams/${encodeURIComponent(teamID)}/${resource}?limit=50`
    const account = accountID ? `&account_id=${encodeURIComponent(accountID)}` : ''
    const page = cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''
    return `${base}${account}${page}`
  }

  return {
    listTeamMembers(teamID, cursor) {
      return request<PagedResponse<TeamMember>>(pagePath(teamID, 'members', cursor))
    },
    listTeamUsage(teamID, cursor, accountID) {
      return request<TeamUsageResponse>(pagePath(teamID, 'usage', cursor, accountID))
    },
  }
}
