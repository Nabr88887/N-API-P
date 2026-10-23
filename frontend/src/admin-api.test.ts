import { afterEach, describe, expect, it, vi } from 'vitest'

import { AdminAPIError, createAdminPortalClient } from './admin-api'
import { rememberCSRFToken } from './portal-session'

afterEach(() => vi.restoreAllMocks())

describe('admin portal client', () => {
  it.each([
    { name: 'authentication failures', status: 401, code: 'AUTHENTICATION_REQUIRED', kind: 'authentication' },
    { name: 'database failures', status: 503, code: 'AUDIT_UNAVAILABLE', kind: 'database' },
    { name: 'server failures', status: 500, code: 'INTERNAL_ERROR', kind: 'server' },
    { name: 'other service unavailable responses', status: 503, code: 'INTERNAL_ERROR', kind: 'server' },
  ])('classifies structured $name with status and code', async ({ status, code, kind }) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: { code } }), { status }))

    await expect(createAdminPortalClient().listAudits()).rejects.toMatchObject({ code, status, kind })
  })

  it('classifies transport failures without exposing the underlying error', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch from a private endpoint'))

    await expect(createAdminPortalClient().listAudits()).rejects.toMatchObject({ code: 'NETWORK_ERROR', kind: 'network' })
    await expect(createAdminPortalClient().listAudits()).rejects.toBeInstanceOf(AdminAPIError)
  })

  it('creates a team with the existing JSON and same-origin CSRF contract', async () => {
    const team = { id: 'team-new', name: 'Internal Test', status: 'active', member_count: 0, created_at: '2026-10-09T01:00:00Z' }
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(team), { status: 201 }))
    rememberCSRFToken('synthetic-team-csrf')
    try {
      const result = await createAdminPortalClient().createTeam('Internal Test')

      expect(result).toEqual(team)
      expect(fetchMock).toHaveBeenCalledWith('/api/v1/teams', expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ name: 'Internal Test' }),
        credentials: 'same-origin',
        cache: 'no-store',
      }))
      const headers = fetchMock.mock.calls[0][1]?.headers as Headers
      expect(headers.get('Content-Type')).toBe('application/json')
      expect(headers.get('X-CSRF-Token')).toBe('synthetic-team-csrf')
    } finally {
      rememberCSRFToken('')
    }
  })

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

  it('keeps investigation grants server-side and views one record at a time', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ case: { id: 'case-1' }, grant: { case_id: 'case-1', expires_at: '2026-09-05T10:00:00Z' } }), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ audit_id: 'audit-1', request: { status: 'complete' }, response: { status: 'unavailable' } }), { status: 200 }))
    const client = createAdminPortalClient()

    await client.createInvestigationCase!({ subject_identity_id: 'employee-1', policy_concern: 'token use', reason: 'incident review', start_at: '2026-09-04T00:00:00Z', end_at: '2026-09-05T00:00:00Z', confirmed: true })
    await client.viewInvestigationAudit!('case/1', 'audit/1')

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/investigation-cases', expect.objectContaining({ method: 'POST', body: expect.not.stringContaining('grant-1') }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/investigation-cases/case%2F1/audits/audit%2F1/raw-views', expect.objectContaining({ method: 'POST', body: '{}' }))
  })

  it('manages elevated audit grants, broad queries, batch views, and cancellable exports', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'grant-1', status: 'active', issued_at: '2026-09-11T09:00:00Z', expires_at: '2026-09-12T09:00:00Z' }), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: [], pagination: { has_more: false } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: [], pagination: { has_more: false } }), { status: 200 }))
      .mockResolvedValueOnce(new Response('audit-jsonl\n', { status: 200, headers: { 'Content-Type': 'application/x-ndjson' } }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = createAdminPortalClient()
    const abortController = new AbortController()

    await client.issueElevatedAuditGrant!('synthetic incident review')
    await client.queryElevatedAudits!({ identity_id: 'employee-1', full_text: 'alpha', limit: 25 })
    await client.batchViewElevatedAudits!(['audit-1', 'audit-2'])
    await client.exportElevatedAudits!({ owner_kind: 'service', limit: 100 }, abortController.signal)
    await client.revokeElevatedAuditGrant!()

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/admin/audit-access/grants', expect.objectContaining({ method: 'POST', body: JSON.stringify({ purpose: 'synthetic incident review' }) }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/audits/query', expect.objectContaining({ method: 'POST', body: JSON.stringify({ identity_id: 'employee-1', full_text: 'alpha', limit: 25 }) }))
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/api/v1/audits/batch', expect.objectContaining({ method: 'POST', body: JSON.stringify({ audit_ids: ['audit-1', 'audit-2'], limit: 1000 }) }))
    expect(fetchMock).toHaveBeenNthCalledWith(4, '/api/v1/audits/exports', expect.objectContaining({ method: 'POST', body: JSON.stringify({ owner_kind: 'service', limit: 100 }) }))
    expect(fetchMock.mock.calls[3][1]).toEqual(expect.objectContaining({ signal: abortController.signal }))
    expect(fetchMock.mock.calls[3][1]).toEqual(expect.objectContaining({ cache: 'no-store' }))
    expect(fetchMock).toHaveBeenNthCalledWith(5, '/api/v1/admin/audit-access/grants/current', expect.objectContaining({ method: 'DELETE' }))
  })

  it('reports a broken export response body as incomplete rather than returning a download', async () => {
    const response = new Response(null, { headers: { 'Content-Type': 'application/x-ndjson' } })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)
    await expect(createAdminPortalClient().exportElevatedAudits!({ limit: 1 })).rejects.toMatchObject({ code: 'EXPORT_INCOMPLETE' })
  })

  it('returns the export response stream without buffering it as a Blob', async () => {
    const response = new Response('synthetic', { headers: { 'Content-Type': 'application/x-ndjson' } })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)

    const stream = await createAdminPortalClient().exportElevatedAudits!({ limit: 1 })

    expect(stream).toBe(response.body)
  })
})
