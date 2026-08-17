import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

import { App } from './App'
import type { AdminPortalClient } from './admin-api'

afterEach(() => cleanup())

describe('audit workspace', () => {
  it('paginates metadata and escapes untrusted model, prompt, and response text', async () => {
    const user = userEvent.setup()
    const client = auditClient()
    render(<App role="system_administrator" adminClient={client} />)

    await user.click(screen.getByRole('link', { name: 'Audit' }))
    const table = await screen.findByRole('table', { name: 'Audit metadata' })
    expect(table).toHaveTextContent('<script>model()</script>')
    expect(document.querySelector('script')).toBeNull()
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /export|bulk/i })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Load more audits' }))
    expect(await screen.findByText('second-model')).toBeInTheDocument()
    expect(client.listAudits).toHaveBeenLastCalledWith({ cursor: 'audits-2' })

    await user.click(screen.getByRole('button', { name: 'Inspect raw content for 84000000-0000-0000-0000-000000000001' }))
    expect(client.inspectAudit).not.toHaveBeenCalled()
    await user.type(screen.getByRole('textbox', { name: 'Investigation reason' }), 'Incident review')
    await user.click(screen.getByRole('button', { name: 'Inspect one record' }))
    const raw = await screen.findByRole('dialog', { name: 'Raw audit record' })
    expect(raw).toHaveTextContent('<script>prompt()</script>')
    expect(raw).toHaveTextContent('<img src=x onerror=response()>')
    expect(document.querySelector('script')).toBeNull()
  })

  it('reauthenticates before retrying one-record inspection and clears raw content on close', async () => {
    const user = userEvent.setup()
    const client = auditClient()
    client.inspectAudit = vi.fn()
      .mockRejectedValueOnce({ code: 'REAUTHENTICATION_REQUIRED' })
      .mockResolvedValueOnce({ audit_id: '84000000-0000-0000-0000-000000000001', request: { prompt: 'private prompt' }, response: { answer: 'private answer' } })
    render(<App role="system_administrator" adminClient={client} />)

    await user.click(screen.getByRole('link', { name: 'Audit' }))
    await screen.findByRole('table', { name: 'Audit metadata' })
    await user.click(screen.getByRole('button', { name: 'Inspect raw content for 84000000-0000-0000-0000-000000000001' }))
    await user.type(screen.getByRole('textbox', { name: 'Investigation reason' }), 'Incident review')
    await user.click(screen.getByRole('button', { name: 'Inspect one record' }))
    expect(await screen.findByRole('dialog', { name: 'Reauthenticate' })).toBeInTheDocument()
    await user.type(screen.getByLabelText('Current password'), 'current-password')
    await user.click(screen.getByRole('button', { name: 'Reauthenticate and continue' }))
    await waitFor(() => expect(client.inspectAudit).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('dialog', { name: 'Raw audit record' })).toHaveTextContent('private prompt')
    await user.click(screen.getByRole('button', { name: 'Close raw audit record' }))
    expect(screen.queryByText('private prompt')).not.toBeInTheDocument()
  })
})

function auditClient(): AdminPortalClient {
  return {
    listAccounts: vi.fn(), listTeams: vi.fn(), disableTeam: vi.fn(), invite: vi.fn(), updateAccount: vi.fn(), addMember: vi.fn(), removeMember: vi.fn(),
    listServiceAccounts: vi.fn(), createServiceAccount: vi.fn(), disableServiceAccount: vi.fn(), listServiceKeys: vi.fn(), createServiceKey: vi.fn(), rotateServiceKey: vi.fn(), revokeServiceKey: vi.fn(),
    getModelAllowlist: vi.fn(), replaceModelAllowlist: vi.fn(), getRetentionPolicy: vi.fn(), replaceRetentionPolicy: vi.fn(), issuePasswordReset: vi.fn(),
    reauthenticate: vi.fn().mockResolvedValue(undefined),
    listAudits: vi.fn()
      .mockResolvedValueOnce({ data: [{ id: '84000000-0000-0000-0000-000000000001', request_id: '87000000-0000-0000-0000-000000000001', key_id: 'key-1', team_id: 'team-1', model_id: '<script>model()</script>', capture_status: 'complete', outcome: 'success', observed_request_bytes: 10, observed_response_bytes: 20, created_at: '2026-08-13T01:00:00Z', updated_at: '2026-08-13T01:01:00Z' }], pagination: { has_more: true, next_cursor: 'audits-2' } })
      .mockResolvedValueOnce({ data: [{ id: '84000000-0000-0000-0000-000000000002', request_id: '87000000-0000-0000-0000-000000000002', key_id: 'key-2', team_id: 'team-1', model_id: 'second-model', capture_status: 'complete', outcome: 'success', observed_request_bytes: 30, observed_response_bytes: 40, created_at: '2026-08-12T01:00:00Z', updated_at: '2026-08-12T01:01:00Z' }], pagination: { has_more: false } }),
    inspectAudit: vi.fn().mockResolvedValue({ audit_id: '84000000-0000-0000-0000-000000000001', request: { prompt: '<script>prompt()</script>' }, response: { answer: '<img src=x onerror=response()>' } }),
    getOperationsHealth: vi.fn().mockResolvedValue({ state: 'healthy', components: [], checked_at: '2026-08-14T09:00:00Z' }),
    listOperationalEvents: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
  }
}
