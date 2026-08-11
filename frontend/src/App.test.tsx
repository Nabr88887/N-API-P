import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

import { App } from './App'
import type { EmployeePortalClient } from './employee-api'
import type { TeamPortalClient } from './team-api'

afterEach(() => cleanup())

describe('App', () => {
  it('identifies the administration work surface', () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: 'N-API-P' })).toBeInTheDocument()
  })

  it('shows only employee navigation for an employee session', () => {
    render(<App role="employee" />)

    expect(screen.getByRole('navigation', { name: 'Primary navigation' })).toHaveTextContent('My keys')
    expect(screen.getByRole('navigation', { name: 'Primary navigation' })).toHaveTextContent('My usage')
    expect(screen.queryByRole('link', { name: 'Audit' })).not.toBeInTheDocument()
  })

  it('shows team navigation without system controls for a team administrator', () => {
    render(<App role="team_administrator" />)

    expect(screen.getByRole('navigation', { name: 'Primary navigation' })).toHaveTextContent('Team members')
    expect(screen.getByRole('navigation', { name: 'Primary navigation' })).toHaveTextContent('Team usage')
    expect(screen.queryByRole('link', { name: 'Service accounts' })).not.toBeInTheDocument()
  })

  it('keeps the system administrator work surface scannable and accessible', async () => {
    const user = userEvent.setup()
    render(<App role="system_administrator" />)

    expect(screen.getByRole('searchbox', { name: 'Search administration' })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Recent activity' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Open session details' }))
    expect(screen.getByRole('dialog', { name: 'Session details' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Close session details' }))
    expect(screen.queryByRole('dialog', { name: 'Session details' })).not.toBeInTheDocument()
  })

  it('loads employee keys and reveals a newly issued credential once', async () => {
    const user = userEvent.setup()
    const client = employeeClient()
    render(<App role="employee" employeeClient={client} />)

    await user.click(screen.getByRole('link', { name: 'My keys' }))
    expect(await screen.findByRole('table', { name: 'Personal API keys' })).toHaveTextContent('workstation')

    await user.click(screen.getByRole('button', { name: 'Create personal key' }))
    await user.type(screen.getByRole('textbox', { name: 'Key name' }), 'laptop')
    await user.click(screen.getByRole('button', { name: 'Create key' }))

    expect(await screen.findByRole('dialog', { name: 'New personal key' })).toHaveTextContent('nap_one_time_secret')
    await user.click(screen.getByRole('button', { name: 'I have saved this key' }))
    expect(screen.queryByText('nap_one_time_secret')).not.toBeInTheDocument()
    expect(client.createPersonalKey).toHaveBeenCalledWith('laptop')
  })

  it('requires confirmation before revoking an employee key', async () => {
    const user = userEvent.setup()
    const client = employeeClient()
    render(<App role="employee" employeeClient={client} />)

    await user.click(screen.getByRole('link', { name: 'My keys' }))
    await screen.findByText('workstation')
    await user.click(screen.getByRole('button', { name: 'Revoke workstation' }))
    expect(client.revokePersonalKey).not.toHaveBeenCalled()
    expect(screen.getByRole('dialog', { name: 'Revoke personal key' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Confirm revoke' }))
    expect(client.revokePersonalKey).toHaveBeenCalledWith('key-1')
  })

  it('loads only the current employee usage view', async () => {
    const user = userEvent.setup()
    const client = employeeClient()
    render(<App role="employee" employeeClient={client} />)

    await user.click(screen.getByRole('link', { name: 'My usage' }))
    expect(await screen.findByRole('table', { name: 'Personal usage' })).toHaveTextContent('gpt-test')
    expect(client.listUsage).toHaveBeenCalledWith()
  })

  it('loads assigned-team membership without credential controls', async () => {
    const user = userEvent.setup()
    const client = teamClient()
    render(<App role="team_administrator" teamID="team-1" teamClient={client} />)

    await user.click(screen.getByRole('link', { name: 'Team members' }))
    expect(await screen.findByRole('table', { name: 'Team members' })).toHaveTextContent('member@example.internal')
    expect(screen.queryByRole('button', { name: /invite|reset|key/i })).not.toBeInTheDocument()
    expect(client.listTeamMembers).toHaveBeenCalledWith('team-1')
  })

  it('shows server-calculated team aggregates and member usage metadata', async () => {
    const user = userEvent.setup()
    const client = teamClient()
    render(<App role="team_administrator" teamID="team-1" teamClient={client} />)

    await user.click(screen.getByRole('link', { name: 'Team usage' }))
    expect(await screen.findByRole('region', { name: 'Team usage summary' })).toHaveTextContent('7')
    expect(screen.getByRole('region', { name: 'Team usage summary' })).toHaveTextContent('100')
    expect(screen.getByRole('table', { name: 'Team usage records' })).toHaveTextContent('gpt-team')
    expect(screen.getByRole('table', { name: 'Team usage records' })).toHaveTextContent('member@example.internal')
    expect(screen.queryByText('raw prompt should never render')).not.toBeInTheDocument()
    expect(client.listTeamUsage).toHaveBeenCalledWith('team-1')

    await user.selectOptions(screen.getByRole('combobox', { name: 'Usage scope' }), 'employee-1')
    await waitFor(() => expect(client.listTeamUsage).toHaveBeenCalledWith('team-1', undefined, 'employee-1'))
  })
})

function employeeClient(): EmployeePortalClient {
  return {
    login: vi.fn().mockResolvedValue(undefined),
    listPersonalKeys: vi.fn().mockResolvedValue({
      data: [{ id: 'key-1', kind: 'personal', owner_account_id: 'employee-1', name: 'workstation', prefix: 'nap_12345678', status: 'active', created_at: '2026-08-11T01:00:00Z' }],
      pagination: { has_more: false },
    }),
    createPersonalKey: vi.fn().mockResolvedValue({
      key: { id: 'key-2', kind: 'personal', owner_account_id: 'employee-1', name: 'laptop', prefix: 'nap_87654321', status: 'active', created_at: '2026-08-11T02:00:00Z' },
      credential: { value: 'nap_one_time_secret' },
    }),
    revokePersonalKey: vi.fn().mockResolvedValue(undefined),
    listUsage: vi.fn().mockResolvedValue({
      data: [{ id: 'usage-1', audit_id: 'audit-1', request_id: 'request-1', key_id: 'key-1', owner_account_id: 'employee-1', team_id: 'team-1', model_id: 'gpt-test', outcome: 'success', usage_reported: true, usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 }, created_at: '2026-08-11T03:00:00Z' }],
      pagination: { has_more: false },
    }),
  }
}

function teamClient(): TeamPortalClient {
  return {
    listTeamMembers: vi.fn().mockResolvedValue({
      data: [{ account_id: 'employee-1', email: 'member@example.internal', role: 'employee', status: 'active', joined_at: '2026-08-11T01:00:00Z' }],
      pagination: { has_more: false },
    }),
    listTeamUsage: vi.fn().mockResolvedValue({
      data: [{ id: 'usage-team-1', audit_id: 'audit-1', request_id: 'request-1', key_id: 'key-1', owner_account_id: 'employee-1', team_id: 'team-1', model_id: 'gpt-team', outcome: 'success', usage_reported: true, usage: { input_tokens: 80, output_tokens: 20, total_tokens: 100 }, created_at: '2026-08-11T03:00:00Z' }],
      pagination: { has_more: false },
      aggregate: { request_count: 7, reported_usage_count: 6, input_tokens: 80, output_tokens: 20, total_tokens: 100 },
    }),
  }
}
