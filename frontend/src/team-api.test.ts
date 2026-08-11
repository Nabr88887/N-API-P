import { afterEach, describe, expect, it, vi } from 'vitest'

import { createTeamPortalClient } from './team-api'

afterEach(() => vi.unstubAllGlobals())

describe('team portal API client', () => {
  it('requests only bounded same-origin team member and usage pages', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: [], pagination: { has_more: true, next_cursor: 'next member' } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: [], pagination: { has_more: false }, aggregate: { request_count: 0, reported_usage_count: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0 } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const client = createTeamPortalClient()

    const members = await client.listTeamMembers('team/assigned')
    await client.listTeamUsage('team/assigned', members.pagination.next_cursor, 'member/selected')

    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/teams/team%2Fassigned/members?limit=50')
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/teams/team%2Fassigned/usage?limit=50&account_id=member%2Fselected&cursor=next%20member')
    expect(fetchMock.mock.calls[0][1].credentials).toBe('same-origin')
    expect(fetchMock.mock.calls[1][1].credentials).toBe('same-origin')
  })
})
