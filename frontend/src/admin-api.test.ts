import { afterEach, describe, expect, it, vi } from 'vitest'

import { createAdminPortalClient } from './admin-api'

afterEach(() => vi.restoreAllMocks())

describe('admin portal client', () => {
  it('keeps account filters bounded and encoded', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ data: [], pagination: { has_more: false } }), { status: 200 }))
    const client = createAdminPortalClient()
    await client.listAccounts({ role: 'employee', status: 'active', cursor: 'opaque cursor' })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/users?limit=50&role=employee&status=active&cursor=opaque+cursor', expect.objectContaining({ credentials: 'same-origin' }))
  })

  it('rotates CSRF evidence and confirms destructive requests', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(null, { status: 204, headers: { 'X-CSRF-Token': 'rotated-csrf' } }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = createAdminPortalClient()
    await client.reauthenticate('current-password')
    await client.revokeServiceKey('service-1', 'key-1')

    const second = fetchMock.mock.calls[1]
    expect((second[1]?.headers as Headers).get('X-CSRF-Token')).toBe('rotated-csrf')
    expect(second[1]?.body).toBe(JSON.stringify({ confirmed: true }))
  })

  it('sends explicit confirmation for team and service-account disablement', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = createAdminPortalClient()

    await client.disableTeam('team-1')
    await client.disableServiceAccount('service-1')

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/teams/team-1', expect.objectContaining({
      method: 'DELETE',
      body: JSON.stringify({ confirmed: true }),
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/service-accounts/service-1', expect.objectContaining({
      method: 'PATCH',
      body: JSON.stringify({ status: 'disabled', confirmed: true }),
    }))
  })

  it('requests bounded audit pages and one raw record with a required reason', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: [], pagination: { has_more: false } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ audit_id: 'audit-1', request: {}, response: {} }), { status: 200 }))
    const client = createAdminPortalClient()

    await client.listAudits({ cursor: 'opaque cursor' })
    await client.inspectAudit('audit/1', 'Incident review')

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/audits?limit=50&cursor=opaque+cursor', expect.objectContaining({ credentials: 'same-origin' }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/audits/audit%2F1/raw-views', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ reason: 'Incident review' }),
    }))
  })

  it('requests current operations health and bounded event pages', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ state: 'healthy', components: [], checked_at: '2026-08-14T09:00:00Z' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: [], pagination: { has_more: false } }), { status: 200 }))
    const client = createAdminPortalClient()

    await client.getOperationsHealth()
    await client.listOperationalEvents({ cursor: 'opaque cursor' })

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/operations/health', expect.objectContaining({ credentials: 'same-origin' }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/operations/events?limit=50&cursor=opaque+cursor', expect.objectContaining({ credentials: 'same-origin' }))
  })

  it('updates an account email through the bounded account endpoint', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }))
    const client = createAdminPortalClient()

    await client.updateAccount('employee/1', { email: 'renamed@example.internal' })

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/users/employee%2F1', expect.objectContaining({
      method: 'PATCH',
      body: JSON.stringify({ email: 'renamed@example.internal' }),
    }))
  })

  it('requests bounded security event pages independently from operations', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ data: [], pagination: { has_more: false } }), { status: 200 }))
    const client = createAdminPortalClient()

    await client.listSecurityEvents!({ cursor: 'opaque cursor' })

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/security-events?limit=50&cursor=opaque+cursor', expect.objectContaining({ credentials: 'same-origin' }))
  })

  it('requests bounded service-key pages with an opaque cursor', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ data: [], pagination: { has_more: false } }), { status: 200 }))
    const client = createAdminPortalClient()

    await client.listServiceKeys('service/1', { cursor: 'opaque cursor' })

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/service-accounts/service%2F1/keys?limit=50&cursor=opaque+cursor', expect.objectContaining({ credentials: 'same-origin' }))
  })
})
