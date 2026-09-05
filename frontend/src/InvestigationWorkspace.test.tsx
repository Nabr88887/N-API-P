import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { InvestigationWorkspace } from './InvestigationWorkspace'
import { AdminAPIError, type AdminPortalClient } from './admin-api'

afterEach(() => { cleanup(); vi.useRealTimers() })

describe('InvestigationWorkspace', () => {
  it('creates a case, lists bounded candidates, and renders partial statuses', async () => {
    const user = userEvent.setup()
    const client = {
      listInvestigationCases: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
      createInvestigationCase: vi.fn().mockResolvedValue({ case: { id: 'case-1', subject_identity_id: 'employee-1', policy_concern: 'token use', reason: 'review', start_at: '2026-09-04T00:00:00Z', end_at: '2026-09-05T00:00:00Z', status: 'open', created_by: 'admin-1', created_at: '2026-09-05T01:00:00Z' }, grant: { case_id: 'case-1', expires_at: '2099-09-05T01:30:00Z' } }),
      issueInvestigationGrant: vi.fn().mockResolvedValue({ case_id: 'case-1', expires_at: '2099-09-05T01:30:00Z' }),
      listInvestigationCandidates: vi.fn().mockResolvedValue({ data: [
        { audit_id: 'audit-1', capture_status: 'incomplete', created_at: '2026-09-05T00:00:00Z', expires_at: '2026-09-06T00:00:00Z' },
        { audit_id: 'audit-2', capture_status: 'complete', created_at: '2026-09-05T00:01:00Z', expires_at: '2026-09-06T00:00:00Z' },
      ], pagination: { has_more: false } }),
      viewInvestigationAudit: vi.fn()
        .mockResolvedValueOnce({ audit_id: 'audit-1', request: { status: 'complete', json: { prompt: 'redacted' } }, response: { status: 'incomplete', fragment: '{"choices":[' } })
        .mockResolvedValueOnce({ audit_id: 'audit-2', request: { status: 'complete', json: { prompt: 'redacted' } }, response: { status: 'unavailable' } }),
    } as unknown as AdminPortalClient
    render(<InvestigationWorkspace client={client} />)
    await user.type(screen.getByLabelText('Employee identity ID'), 'employee-1')
    await user.type(screen.getByLabelText('Policy concern'), 'token use')
    await user.type(screen.getByLabelText('Investigation reason'), 'review')
    fireEvent.change(screen.getByLabelText('Start'), { target: { value: '2026-09-04T00:00' } })
    fireEvent.change(screen.getByLabelText('End'), { target: { value: '2026-09-05T00:00' } })
    await user.click(screen.getByLabelText('I confirm this investigation scope'))
    await user.click(screen.getByRole('button', { name: 'Create investigation' }))
    await waitFor(() => expect(client.createInvestigationCase).toHaveBeenCalled())
    await waitFor(() => expect(screen.getByRole('table', { name: 'Investigation candidates' })).toHaveTextContent('incomplete'))
    await user.click(screen.getAllByRole('button', { name: 'View one record' })[0])
    expect(await screen.findByText('Response: incomplete')).toBeInTheDocument()
    expect(screen.getByText('{"choices":[')).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: 'View one record' })[1])
    expect(await screen.findByText('Response: unavailable')).toBeInTheDocument()
  })

  it('requires explicit authorization before loading an existing open case', async () => {
    const user = userEvent.setup()
    const client = {
      listInvestigationCases: vi.fn().mockResolvedValue({ data: [{ id: 'case-2', subject_identity_id: 'employee-2', policy_concern: 'token use', reason: 'review', start_at: '2026-09-04T00:00:00Z', end_at: '2026-09-05T00:00:00Z', status: 'open', created_by: 'admin-1', created_at: '2026-09-05T01:00:00Z' }], pagination: { has_more: false } }),
      issueInvestigationGrant: vi.fn().mockResolvedValue({ case_id: 'case-2', expires_at: '2099-09-05T01:30:00Z' }),
      listInvestigationCandidates: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
    } as unknown as AdminPortalClient
    render(<InvestigationWorkspace client={client} />)
    await user.click(await screen.findByRole('button', { name: 'Open case' }))
    expect(client.listInvestigationCandidates).toHaveBeenCalledWith('case-2')
    expect(client.issueInvestigationGrant).not.toHaveBeenCalled()
    await user.click(await screen.findByRole('button', { name: 'Authorize access' }))
    await waitFor(() => expect(client.issueInvestigationGrant).toHaveBeenCalledWith('case-2'))
  })

  it('reauthenticates and retries case creation, then clears plaintext on confirmed closure', async () => {
    const user = userEvent.setup()
    const investigationCase = { id: 'case-3', subject_identity_id: 'employee-3', policy_concern: 'token use', reason: 'review', start_at: '2026-09-04T00:00:00Z', end_at: '2026-09-05T00:00:00Z', status: 'open' as const, created_by: 'admin-1', created_at: '2026-09-05T01:00:00Z' }
    const client = {
      listInvestigationCases: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
      createInvestigationCase: vi.fn()
        .mockRejectedValueOnce(new AdminAPIError('REAUTHENTICATION_REQUIRED'))
        .mockResolvedValueOnce({ case: investigationCase, grant: { case_id: 'case-3', expires_at: '2099-09-05T01:30:00Z' } }),
      listInvestigationCandidates: vi.fn().mockResolvedValue({ data: [{ audit_id: 'audit-3', capture_status: 'complete', created_at: '2026-09-05T00:00:00Z', expires_at: '2099-09-06T00:00:00Z' }], pagination: { has_more: false } }),
      viewInvestigationAudit: vi.fn().mockResolvedValue({ audit_id: 'audit-3', request: { status: 'complete', json: { prompt: 'sensitive' } }, response: { status: 'complete', json: { answer: 'sensitive' } } }),
      closeInvestigationCase: vi.fn().mockRejectedValueOnce(new AdminAPIError('REAUTHENTICATION_REQUIRED')).mockResolvedValueOnce(undefined),
      reauthenticate: vi.fn().mockResolvedValue(undefined),
    } as unknown as AdminPortalClient
    render(<InvestigationWorkspace client={client} />)

    await user.type(screen.getByLabelText('Employee identity ID'), 'employee-3')
    await user.type(screen.getByLabelText('Policy concern'), 'token use')
    await user.type(screen.getByLabelText('Investigation reason'), 'review')
    fireEvent.change(screen.getByLabelText('Start'), { target: { value: '2026-09-04T00:00' } })
    fireEvent.change(screen.getByLabelText('End'), { target: { value: '2026-09-05T00:00' } })
    expect(screen.getByRole('button', { name: 'Create investigation' })).toBeDisabled()
    await user.click(screen.getByLabelText('I confirm this investigation scope'))
    await user.click(screen.getByRole('button', { name: 'Create investigation' }))
    const createReauth = await screen.findByRole('dialog', { name: 'Reauthenticate' })
    await user.type(within(createReauth).getByLabelText('Current password'), 'current-password')
    await user.click(within(createReauth).getByRole('button', { name: 'Reauthenticate and continue' }))
    await waitFor(() => expect(client.createInvestigationCase).toHaveBeenCalledTimes(2))

    await user.click(await screen.findByRole('button', { name: 'View one record' }))
    await waitFor(() => expect(screen.getAllByText(/sensitive/).length).toBe(2))
    expect(screen.getByRole('button', { name: 'Close case' })).toBeDisabled()
    await user.selectOptions(screen.getByLabelText('Disposition'), 'confirmed_violation')
    await user.click(screen.getByLabelText('I confirm this case closure'))
    await user.click(screen.getByRole('button', { name: 'Close case' }))
    const closeReauth = await screen.findByRole('dialog', { name: 'Reauthenticate' })
    await user.type(within(closeReauth).getByLabelText('Current password'), 'current-password')
    await user.click(within(closeReauth).getByRole('button', { name: 'Reauthenticate and continue' }))
    await waitFor(() => expect(client.closeInvestigationCase).toHaveBeenCalledTimes(2))
    expect(client.closeInvestigationCase).toHaveBeenLastCalledWith('case-3', 'confirmed_violation', '')
    expect(screen.queryByText(/sensitive/)).not.toBeInTheDocument()
  })

  it('clears displayed plaintext when the case grant expires', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-09-05T01:00:00Z'))
    const investigationCase = { id: 'case-4', subject_identity_id: 'employee-4', policy_concern: 'token use', reason: 'review', start_at: '2026-09-04T00:00:00Z', end_at: '2026-09-05T00:00:00Z', status: 'open' as const, created_by: 'admin-1', created_at: '2026-09-05T01:00:00Z' }
    const client = {
      listInvestigationCases: vi.fn().mockResolvedValue({ data: [investigationCase], pagination: { has_more: false } }),
      listInvestigationCandidates: vi.fn().mockResolvedValue({ data: [{ audit_id: 'audit-4', capture_status: 'complete', created_at: '2026-09-05T00:00:00Z', expires_at: '2026-09-06T00:00:00Z' }], pagination: { has_more: false } }),
      issueInvestigationGrant: vi.fn().mockResolvedValue({ case_id: 'case-4', expires_at: '2026-09-05T01:01:00Z' }),
      viewInvestigationAudit: vi.fn().mockResolvedValue({ audit_id: 'audit-4', request: { status: 'complete', json: { prompt: 'sensitive' } }, response: { status: 'complete', json: { answer: 'sensitive' } } }),
    } as unknown as AdminPortalClient
    render(<InvestigationWorkspace client={client} />)
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    fireEvent.click(screen.getByRole('button', { name: 'Open case' }))
    await act(async () => { await Promise.resolve() })
    fireEvent.click(screen.getByRole('button', { name: 'Authorize access' }))
    await act(async () => { await Promise.resolve() })
    fireEvent.click(screen.getByRole('button', { name: 'View one record' }))
    await act(async () => { await Promise.resolve() })
    expect(screen.getAllByText(/sensitive/)).toHaveLength(2)
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(screen.queryByText(/sensitive/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'View one record' })).toBeDisabled()
  })

  it('explains when the selected scope must be narrowed', async () => {
    const user = userEvent.setup()
    const client = {
      listInvestigationCases: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
      createInvestigationCase: vi.fn().mockRejectedValue(new AdminAPIError('INVESTIGATION_SCOPE_TOO_BROAD')),
    } as unknown as AdminPortalClient
    render(<InvestigationWorkspace client={client} />)
    await user.type(screen.getByLabelText('Employee identity ID'), 'employee-4')
    await user.type(screen.getByLabelText('Policy concern'), 'token use')
    await user.type(screen.getByLabelText('Investigation reason'), 'review')
    fireEvent.change(screen.getByLabelText('Start'), { target: { value: '2026-09-04T00:00' } })
    fireEvent.change(screen.getByLabelText('End'), { target: { value: '2026-09-05T00:00' } })
    await user.click(screen.getByLabelText('I confirm this investigation scope'))
    await user.click(screen.getByRole('button', { name: 'Create investigation' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('More than 100 retained audit records matched this scope; narrow the time range.')
  })

  it('loads additional investigation case pages without replacing the first page', async () => {
    const user = userEvent.setup()
    const firstCase = { id: 'case-page-1', subject_identity_id: 'employee-1', policy_concern: 'token use', reason: 'review', start_at: '2026-09-04T00:00:00Z', end_at: '2026-09-05T00:00:00Z', status: 'closed' as const, created_by: 'admin-1', created_at: '2026-09-05T02:00:00Z' }
    const secondCase = { ...firstCase, id: 'case-page-2', subject_identity_id: 'employee-2', created_at: '2026-09-05T01:00:00Z' }
    const client = {
      listInvestigationCases: vi.fn()
        .mockResolvedValueOnce({ data: [firstCase], pagination: { has_more: true, next_cursor: 'cursor-1' } })
        .mockResolvedValueOnce({ data: [secondCase], pagination: { has_more: false } }),
    } as unknown as AdminPortalClient
    render(<InvestigationWorkspace client={client} />)

    await user.click(await screen.findByRole('button', { name: 'Load more investigation cases' }))
    expect(await screen.findByText('employee-2')).toBeInTheDocument()
    expect(screen.getByText('employee-1')).toBeInTheDocument()
    expect(client.listInvestigationCases).toHaveBeenLastCalledWith({ cursor: 'cursor-1' })
    expect(screen.queryByRole('button', { name: 'Load more investigation cases' })).not.toBeInTheDocument()
  })

  it('keeps the most recently requested raw view when earlier requests finish later', async () => {
    const user = userEvent.setup()
    const firstCase = { id: 'case-race', subject_identity_id: 'employee-race', policy_concern: 'token use', reason: 'review', start_at: '2026-09-04T00:00:00Z', end_at: '2026-09-05T00:00:00Z', status: 'open' as const, created_by: 'admin-1', created_at: '2026-09-05T01:00:00Z' }
    const candidates = [
      { audit_id: 'audit-a', capture_status: 'complete' as const, created_at: '2026-09-05T00:00:00Z', expires_at: '2099-09-06T00:00:00Z' },
      { audit_id: 'audit-b', capture_status: 'complete' as const, created_at: '2026-09-05T00:01:00Z', expires_at: '2099-09-06T00:00:00Z' },
    ]
    let resolveFirst!: (value: unknown) => void
    let resolveSecond!: (value: unknown) => void
    const firstView = new Promise((resolve) => { resolveFirst = resolve })
    const secondView = new Promise((resolve) => { resolveSecond = resolve })
    const client = {
      listInvestigationCases: vi.fn().mockResolvedValue({ data: [firstCase], pagination: { has_more: false } }),
      listInvestigationCandidates: vi.fn().mockResolvedValue({ data: candidates, pagination: { has_more: false } }),
      issueInvestigationGrant: vi.fn().mockResolvedValue({ case_id: 'case-race', expires_at: '2099-09-05T01:30:00Z' }),
      viewInvestigationAudit: vi.fn((_: string, auditID: string) => auditID === 'audit-a' ? firstView : secondView),
    } as unknown as AdminPortalClient
    render(<InvestigationWorkspace client={client} />)
    await user.click(await screen.findByRole('button', { name: 'Open case' }))
    await user.click(await screen.findByRole('button', { name: 'Authorize access' }))
    const viewButtons = await screen.findAllByRole('button', { name: 'View one record' })
    await user.click(viewButtons[0])
    await user.click(viewButtons[1])

    resolveSecond({ audit_id: 'audit-b', request: { status: 'complete', json: { marker: 'second' } }, response: { status: 'complete', json: { marker: 'second' } } })
    expect(await screen.findByText('Record audit-b')).toBeInTheDocument()
    resolveFirst({ audit_id: 'audit-a', request: { status: 'complete', json: { marker: 'first' } }, response: { status: 'complete', json: { marker: 'first' } } })
    await act(async () => { await Promise.resolve() })
    expect(screen.getByText('Record audit-b')).toBeInTheDocument()
    expect(screen.queryByText('Record audit-a')).not.toBeInTheDocument()
  })
})
