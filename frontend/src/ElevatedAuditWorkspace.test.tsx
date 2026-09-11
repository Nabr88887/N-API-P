import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ElevatedAuditWorkspace } from './ElevatedAuditWorkspace'
import { AdminAPIError, type AdminPortalClient, type ElevatedAuditRecord } from './admin-api'

afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks() })

function client(overrides: Partial<AdminPortalClient> = {}): AdminPortalClient {
  return {
    listAccounts: vi.fn(), listTeams: vi.fn(), disableTeam: vi.fn(), invite: vi.fn(), updateAccount: vi.fn(), addMember: vi.fn(), removeMember: vi.fn(), listServiceAccounts: vi.fn(), createServiceAccount: vi.fn(), disableServiceAccount: vi.fn(), listServiceKeys: vi.fn(), createServiceKey: vi.fn(), rotateServiceKey: vi.fn(), revokeServiceKey: vi.fn(), getModelAllowlist: vi.fn(), replaceModelAllowlist: vi.fn(), getRetentionPolicy: vi.fn(), replaceRetentionPolicy: vi.fn(), issuePasswordReset: vi.fn(), listAudits: vi.fn(), inspectAudit: vi.fn(), getOperationsHealth: vi.fn(), listOperationalEvents: vi.fn(), listSecurityEvents: vi.fn(), reauthenticate: vi.fn(),
    issueElevatedAuditGrant: vi.fn().mockResolvedValue({ id: 'grant-1', status: 'active', issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString() }),
    revokeElevatedAuditGrant: vi.fn().mockResolvedValue(undefined),
    queryElevatedAudits: vi.fn().mockResolvedValue({ data: [{ id: 'audit-1', request_id: 'req-1', owner_kind: 'personal', identity_id: 'employee-1', team_id: 'team-1', model_id: 'model-1', request_capture_status: 'complete', response_capture_status: 'complete', outcome: 'success', created_at: '2026-09-11T09:00:00Z', updated_at: '2026-09-11T09:00:00Z', request: { prompt: 'synthetic' }, response: { answer: 'synthetic' } }], pagination: { has_more: false } }),
    batchViewElevatedAudits: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
    exportElevatedAudits: vi.fn().mockResolvedValue(new Blob(['{"id":"audit-1"}\n'], { type: 'application/x-ndjson' })),
    ...overrides,
  } as AdminPortalClient
}

describe('ElevatedAuditWorkspace', () => {
  it('displays bounded fragments as partial captures', async () => {
    const record = { ...syntheticRecord('partial-audit'), request: undefined, request_capture_status: 'truncated', request_fragment: 'synthetic partial fragment' }
    render(<ElevatedAuditWorkspace client={client({ queryElevatedAudits: vi.fn().mockResolvedValue({ data: [record], pagination: { has_more: false } }) })} />)
    await activateGrant()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Search retained audits' })) })
    expect(screen.getByText('synthetic partial fragment')).toBeInTheDocument()
  })
  it('clears expired results, aborts export, and ignores a late batch response after reactivation', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-09-11T09:00:00Z'))
    let finishBatch!: (page: { data: ElevatedAuditRecord[]; pagination: { has_more: boolean } }) => void
    let signal: AbortSignal | undefined
    const admin = client({
      batchViewElevatedAudits: vi.fn().mockImplementation(() => new Promise((resolve) => { finishBatch = resolve })),
      exportElevatedAudits: vi.fn().mockImplementation((_query, receivedSignal) => { signal = receivedSignal; return new Promise(() => {}) }),
    })
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    render(<ElevatedAuditWorkspace client={admin} />)
    await activateGrant()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Search retained audits' })) })
    fireEvent.click(screen.getByLabelText('Select audit audit-1'))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Export JSONL' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'View selected audits' })) })
    await act(async () => { await vi.advanceTimersByTimeAsync(60_001) })
    expect(signal?.aborted).toBe(true)
    expect(screen.queryByText('audit-1')).not.toBeInTheDocument()
    vi.mocked(admin.issueElevatedAuditGrant!).mockResolvedValue({ id: 'grant-2', status: 'active', issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString() })
    await activateGrant()
    await act(async () => { finishBatch({ data: [syntheticRecord('stale-audit')], pagination: { has_more: false } }) })
    expect(screen.queryByText('stale-audit')).not.toBeInTheDocument()
    expect(storage).not.toHaveBeenCalled()
  })

  it('keeps only the active page and continues the submitted query after filter edits', async () => {
    const query = vi.fn().mockResolvedValueOnce({ data: [syntheticRecord('audit-1')], pagination: { has_more: true, next_cursor: 'cursor-1' } }).mockResolvedValueOnce({ data: [syntheticRecord('audit-2')], pagination: { has_more: false } })
    render(<ElevatedAuditWorkspace client={client({ queryElevatedAudits: query })} />)
    await activateGrant()
    fireEvent.change(screen.getByLabelText('Full-text filter'), { target: { value: 'first' } })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Search retained audits' })) })
    fireEvent.change(screen.getByLabelText('Full-text filter'), { target: { value: 'edited' } })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Load more retained audits' })) })
    expect(query).toHaveBeenLastCalledWith(expect.objectContaining({ full_text: 'first', cursor: 'cursor-1' }))
    expect(screen.queryByText('audit-1')).not.toBeInTheDocument()
    expect(screen.getByText('audit-2')).toBeInTheDocument()
  })

  it('renders every batch record and removes prior content on grant rejection', async () => {
    const query = vi.fn().mockResolvedValueOnce({ data: [syntheticRecord('audit-1'), syntheticRecord('audit-2')], pagination: { has_more: false } }).mockRejectedValueOnce(new AdminAPIError('GRANT_REVOKED'))
    render(<ElevatedAuditWorkspace client={client({ queryElevatedAudits: query })} />)
    await activateGrant()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Search retained audits' })) })
    expect(screen.getByText(/synthetic-body-audit-2/)).toBeInTheDocument()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Search retained audits' })) })
    await activateGrant()
    expect(screen.queryByText('audit-1')).not.toBeInTheDocument()
  })

  it('completes the existing security check before retrying grant issuance', async () => {
    const issue = vi.fn().mockRejectedValueOnce(new AdminAPIError('REAUTHENTICATION_REQUIRED')).mockResolvedValueOnce({ id: 'grant-1', status: 'active', issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString() })
    const admin = client({ issueElevatedAuditGrant: issue, reauthenticate: vi.fn().mockResolvedValue(undefined) })
    render(<ElevatedAuditWorkspace client={admin} />)
    await activateGrant()
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'synthetic-test-only' } })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Complete security check' })) })
    expect(admin.reauthenticate).toHaveBeenCalledWith('synthetic-test-only')
    expect(issue).toHaveBeenCalledTimes(2)
    expect(screen.queryByLabelText('Current password')).not.toBeInTheDocument()
    expect(screen.getByText(/Grant active/)).toBeInTheDocument()
  })
  it('issues a grant, searches, batch views, and revokes without persistent raw storage', async () => {
    const admin = client()
    render(<ElevatedAuditWorkspace client={admin} />)

    fireEvent.change(screen.getByLabelText('Grant purpose'), { target: { value: 'Synthetic review' } })
    fireEvent.click(screen.getByRole('button', { name: 'Activate 24-hour audit access' }))
    await waitFor(() => expect(screen.getByText(/Grant active/)).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Search retained audits' }))
    await waitFor(() => expect(screen.getByText('audit-1')).toBeInTheDocument())
    fireEvent.click(screen.getByLabelText('Select audit audit-1'))
    fireEvent.click(screen.getByRole('button', { name: 'View selected audits' }))
    await waitFor(() => expect(admin.batchViewElevatedAudits).toHaveBeenCalledWith(['audit-1']))
    fireEvent.click(screen.getByRole('button', { name: 'Revoke audit access' }))
    await waitFor(() => expect(screen.getByText('Audit access revoked')).toBeInTheDocument())
  })

  it('reports export cancellation and grant expiry without storing output', async () => {
    const abort = vi.fn()
    const admin = client({ exportElevatedAudits: vi.fn().mockRejectedValue(Object.assign(new Error('cancelled'), { name: 'AbortError' })) })
    render(<ElevatedAuditWorkspace client={admin} />)
    fireEvent.change(screen.getByLabelText('Grant purpose'), { target: { value: 'Synthetic export' } })
    fireEvent.click(screen.getByRole('button', { name: 'Activate 24-hour audit access' }))
    await waitFor(() => expect(screen.getByText(/Grant active/)).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Export JSONL' }))
    await waitFor(() => expect(screen.getByText('Export cancelled.')).toBeInTheDocument())
    expect(abort).not.toHaveBeenCalled()
  })
})

async function activateGrant() {
  fireEvent.change(screen.getByLabelText('Grant purpose'), { target: { value: 'Synthetic review' } })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Activate 24-hour audit access' })) })
}

function syntheticRecord(id: string): ElevatedAuditRecord {
  return { id, request_id: 'synthetic-request', owner_kind: 'personal', team_id: 'synthetic-team', model_id: 'synthetic-model', request_capture_status: 'complete', response_capture_status: 'unavailable', outcome: 'success', created_at: '2026-09-11T09:00:00Z', updated_at: '2026-09-11T09:00:00Z', request: { prompt: `synthetic-body-${id}` } }
}
