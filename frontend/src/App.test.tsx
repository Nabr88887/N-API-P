import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

import { App } from './App'
import type { EmployeePortalClient, KeyIssuance } from './employee-api'
import type { TeamPortalClient } from './team-api'
import type { AdminPortalClient, HealthResponse, Team } from './admin-api'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

describe('App', () => {
  it('identifies the administration work surface', () => {
    render(<App />)

    expect(screen.getByText('N-API-P')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument()
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

    expect(screen.getByRole('table', { name: 'Recent activity' })).toBeInTheDocument()
    expect(screen.getByText('Activity data is not available in this overview.')).toBeInTheDocument()
    expect(screen.queryByText('Mira Chen')).not.toBeInTheDocument()
    expect(screen.queryByText('1,248')).not.toBeInTheDocument()
    expect(screen.queryByText('12 models available')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Open session details' }))
    expect(screen.getByRole('dialog', { name: 'Session details' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Close session details' }))
    expect(screen.queryByRole('dialog', { name: 'Session details' })).not.toBeInTheDocument()
  })

  it('keeps allowlisted critical faults visible across system administration sections', async () => {
    const user = userEvent.setup()
    const client = adminClient()
    client.getOperationsHealth = vi.fn().mockResolvedValue({
      state: 'unhealthy',
      components: [
        { name: 'audit_unavailable', state: 'unhealthy', detail_code: 'SQL password=secret', checked_at: '2026-08-14T09:00:00Z' },
        { name: 'unknown_internal_fault', state: 'unhealthy', detail_code: 'C:\\secrets\\audit.key', checked_at: '2026-08-14T09:00:00Z' },
      ],
      checked_at: '2026-08-14T09:00:00Z',
    })
    render(<App role="system_administrator" adminClient={client} />)

    expect(await screen.findByRole('alert', { name: 'Audit persistence unavailable' })).toBeInTheDocument()
    expect(screen.queryByText(/password=secret|secrets|unknown_internal_fault/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('link', { name: 'People & teams' }))
    await screen.findByRole('table', { name: 'Accounts' })
    expect(screen.getByRole('alert', { name: 'Audit persistence unavailable' })).toBeInTheDocument()
  })

  it('shows a fixed database fault when operations health cannot be read', async () => {
    const client = adminClient()
    client.getOperationsHealth = vi.fn().mockRejectedValue(new Error('dial /private/socket password=secret'))
    render(<App role="system_administrator" adminClient={client} />)

    expect(await screen.findByRole('alert', { name: 'Database unavailable' })).toBeInTheDocument()
    expect(screen.queryByText(/private\/socket|password=secret/)).not.toBeInTheDocument()
  })

  it('refreshes critical faults and clears banners only after verified recovery', async () => {
    vi.useFakeTimers()
    const client = adminClient()
    client.getOperationsHealth = vi.fn()
      .mockResolvedValueOnce({ state: 'healthy', components: [], checked_at: '2026-08-14T09:00:00Z' })
      .mockResolvedValueOnce({ state: 'unhealthy', components: [{ name: 'required_key_failure', state: 'unhealthy', checked_at: '2026-08-14T09:00:30Z' }], checked_at: '2026-08-14T09:00:30Z' })
      .mockResolvedValueOnce({ state: 'healthy', components: [], checked_at: '2026-08-14T09:01:00Z' })

    await act(async () => {
      render(<App role="system_administrator" adminClient={client} />)
      await Promise.resolve()
    })
    expect(client.getOperationsHealth).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('alert', { name: 'Required audit key unavailable' })).not.toBeInTheDocument()

    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    expect(screen.getByRole('alert', { name: 'Required audit key unavailable' })).toBeInTheDocument()

    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    expect(screen.queryByRole('alert', { name: 'Required audit key unavailable' })).not.toBeInTheDocument()
    expect(client.getOperationsHealth).toHaveBeenCalledTimes(3)
  })

  it('does not overlap operations health refreshes', async () => {
    vi.useFakeTimers()
    let resolveFirstHealth: (health: HealthResponse) => void = () => {}
    const client = adminClient()
    client.getOperationsHealth = vi.fn()
      .mockImplementationOnce(() => new Promise<HealthResponse>((resolve) => { resolveFirstHealth = resolve }))
      .mockResolvedValue({ state: 'healthy', components: [], checked_at: '2026-08-14T09:01:30Z' })

    render(<App role="system_administrator" adminClient={client} />)
    expect(client.getOperationsHealth).toHaveBeenCalledTimes(1)

    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(client.getOperationsHealth).toHaveBeenCalledTimes(1)

    await act(async () => {
      resolveFirstHealth({ state: 'healthy', components: [], checked_at: '2026-08-14T09:01:00Z' })
      await Promise.resolve()
    })
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    expect(client.getOperationsHealth).toHaveBeenCalledTimes(2)
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

  it('locks personal key creation while the request is pending', async () => {
    const user = userEvent.setup()
    const client = employeeClient()
    let resolveCreate: (value: KeyIssuance) => void = () => {}
    client.createPersonalKey = vi.fn().mockImplementation(() => new Promise<KeyIssuance>((resolve) => { resolveCreate = resolve }))
    render(<App role="employee" employeeClient={client} />)

    await user.click(screen.getByRole('link', { name: 'My keys' }))
    await screen.findByRole('table', { name: 'Personal API keys' })
    await user.click(screen.getByRole('button', { name: 'Create personal key' }))
    await user.type(screen.getByRole('textbox', { name: 'Key name' }), 'laptop')
    await user.click(screen.getByRole('button', { name: 'Create key' }))

    const pendingButton = await screen.findByRole('button', { name: 'Creating…' })
    expect(pendingButton).toBeDisabled()
    await user.click(pendingButton)
    expect(client.createPersonalKey).toHaveBeenCalledOnce()

    await act(async () => resolveCreate({
      key: { id: 'key-2', kind: 'personal', owner_account_id: 'employee-1', name: 'laptop', prefix: 'nap_87654321', status: 'active', created_at: '2026-08-11T02:00:00Z' },
      credential: { value: 'nap_one_time_secret' },
    }))
    expect(await screen.findByRole('dialog', { name: 'New personal key' })).toBeInTheDocument()
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

  it('lets a team administrator switch between every assigned team', async () => {
    const user = userEvent.setup()
    const client = teamClient()
    client.listTeamMembers = vi.fn().mockImplementation(async (teamID: string) => ({
      data: [{ account_id: `employee-${teamID}`, email: `${teamID}@example.internal`, role: 'employee', status: 'active', joined_at: '2026-08-11T01:00:00Z' }],
      pagination: { has_more: false },
    }))
    render(<App role="team_administrator" teamID="team-1" teamIDs={['team-1', 'team-2']} teamClient={client} />)

    await user.click(screen.getByRole('link', { name: 'Team members' }))
    expect(await screen.findByText('team-1@example.internal')).toBeInTheDocument()
    await user.selectOptions(screen.getByRole('combobox', { name: 'Team scope' }), 'team-2')
    expect(await screen.findByText('team-2@example.internal')).toBeInTheDocument()
    expect(client.listTeamMembers).toHaveBeenCalledWith('team-2')
  })

  it('loads every member page before offering a team usage scope', async () => {
    const user = userEvent.setup()
    const client = teamClient()
    client.listTeamMembers = vi.fn()
      .mockResolvedValueOnce({ data: [{ account_id: 'employee-1', email: 'first@example.internal', role: 'employee', status: 'active', joined_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: true, next_cursor: 'members-2' } })
      .mockResolvedValueOnce({ data: [{ account_id: 'employee-2', email: 'second@example.internal', role: 'employee', status: 'active', joined_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: false } })
    render(<App role="team_administrator" teamID="team-1" teamClient={client} />)

    await user.click(screen.getByRole('link', { name: 'Team usage' }))
    expect(await screen.findByRole('combobox', { name: 'Usage scope' })).toHaveTextContent('second@example.internal')
    expect(client.listTeamMembers).toHaveBeenLastCalledWith('team-1', 'members-2')
  })

  it('keeps team member pagination retryable after a failed page', async () => {
    const user = userEvent.setup()
    const client = teamClient()
    client.listTeamMembers = vi.fn()
      .mockResolvedValueOnce({ data: [{ account_id: 'employee-1', email: 'first@example.internal', role: 'employee', status: 'active', joined_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: true, next_cursor: 'members-2' } })
      .mockRejectedValueOnce(new Error('temporary failure'))
      .mockResolvedValueOnce({ data: [{ account_id: 'employee-2', email: 'second@example.internal', role: 'employee', status: 'active', joined_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: false } })
    render(<App role="team_administrator" teamID="team-1" teamClient={client} />)

    await user.click(screen.getByRole('link', { name: 'Team members' }))
    await screen.findByText('first@example.internal')
    await user.click(screen.getByRole('button', { name: 'Load more members' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load more members.')
    await user.click(screen.getByRole('button', { name: 'Load more members' }))
    expect(await screen.findByText('second@example.internal')).toBeInTheDocument()
  })

  it('creates the first team and makes it available for an employee invitation', async () => {
    const user = userEvent.setup()
    const client = adminClient()
    client.listTeams = vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } })
    render(<App role="system_administrator" adminClient={client} />)
    await user.click(screen.getByRole('link', { name: 'People & teams' }))
    await screen.findByRole('table', { name: 'Teams' })
    expect(screen.getByRole('button', { name: 'Invite employee' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Create team' }))
    const dialog = screen.getByRole('dialog', { name: 'Create team' })
    await user.type(within(dialog).getByLabelText('Team name'), '  Internal Test  ')
    await user.click(within(dialog).getByRole('button', { name: 'Create team' }))

    expect(client.createTeam).toHaveBeenCalledWith('Internal Test')
    expect(screen.queryByRole('dialog', { name: 'Create team' })).not.toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Teams' })).getByRole('row', { name: /Internal Test active 0/ })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Invite employee' }))
    expect(screen.getByLabelText('Assigned team')).toHaveValue('team-new')
    expect(screen.getByLabelText('Assigned team')).toHaveTextContent('Internal Test')
    await user.type(screen.getByLabelText('Company email'), 'new@example.internal')
    await user.click(screen.getByRole('button', { name: 'Create invitation' }))
    expect(client.invite).toHaveBeenCalledWith('new@example.internal', 'team-new')
  })

  it('keeps team creation errors in the dialog and preserves the name for retry', async () => {
    const user = userEvent.setup()
    const client = adminClient()
    vi.mocked(client.createTeam).mockRejectedValueOnce(new Error('private database details'))
    render(<App role="system_administrator" adminClient={client} />)
    await user.click(screen.getByRole('link', { name: 'People & teams' }))
    await user.click(await screen.findByRole('button', { name: 'Create team' }))
    const dialog = screen.getByRole('dialog', { name: 'Create team' })
    await user.type(within(dialog).getByLabelText('Team name'), 'Internal Test')
    await user.click(within(dialog).getByRole('button', { name: 'Create team' }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Unable to create this team.')
    expect(within(dialog).getByLabelText('Team name')).toHaveValue('Internal Test')
    expect(screen.queryByText('private database details')).not.toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Teams' })).toHaveTextContent('Platform')
    await user.click(within(dialog).getByRole('button', { name: 'Create team' }))
    expect(screen.getByRole('table', { name: 'Teams' })).toHaveTextContent('Internal Test')
    expect(screen.getByRole('table', { name: 'Teams' })).toHaveTextContent('Platform')
    await user.click(screen.getByRole('button', { name: 'Create team' }))
    expect(screen.getByLabelText('Team name')).toHaveValue('')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('rejects blank team names and prevents duplicate creation while pending', async () => {
    const user = userEvent.setup()
    const client = adminClient()
    let complete!: (team: Team) => void
    client.createTeam = vi.fn().mockReturnValue(new Promise<Team>((resolve) => { complete = resolve }))
    render(<App role="system_administrator" adminClient={client} />)
    await user.click(screen.getByRole('link', { name: 'People & teams' }))
    await user.click(await screen.findByRole('button', { name: 'Create team' }))
    const dialog = screen.getByRole('dialog', { name: 'Create team' })
    const name = within(dialog).getByLabelText('Team name')
    const submit = within(dialog).getByRole('button', { name: 'Create team' })
    expect(submit).toBeDisabled()
    await user.type(name, '   ')
    await user.keyboard('{Enter}')
    expect(client.createTeam).not.toHaveBeenCalled()
    await user.clear(name)
    await user.type(name, 'Internal Test')
    await user.dblClick(submit)
    expect(client.createTeam).toHaveBeenCalledTimes(1)
    expect(submit).toBeDisabled()
    expect(name).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(dialog).toBeInTheDocument()
    await act(async () => complete({ id: 'team-new', name: 'Internal Test', status: 'active', member_count: 0, created_at: '2026-10-09T01:00:00Z' }))
    expect(screen.queryByRole('dialog', { name: 'Create team' })).not.toBeInTheDocument()
  })

  it('invites an employee and reveals the activation value once', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'People & teams' }))
	await screen.findByRole('table', { name: 'Accounts' })
	await user.click(screen.getByRole('button', { name: 'Invite employee' }))
	await user.type(screen.getByRole('textbox', { name: 'Company email' }), 'new@example.internal')
	await user.selectOptions(screen.getByRole('combobox', { name: 'Assigned team' }), 'team-1')
	await user.click(screen.getByRole('button', { name: 'Create invitation' }))
	expect(await screen.findByRole('dialog', { name: 'New invitation' })).toHaveTextContent('activation-once')
	await user.click(screen.getByRole('button', { name: 'I have saved this value' }))
	expect(screen.queryByText('activation-once')).not.toBeInTheDocument()
	expect(client.invite).toHaveBeenCalledWith('new@example.internal', 'team-1')
  })

  it('offers invitations only for active teams and recovery only for active employees', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.listTeams = vi.fn().mockResolvedValue({ data: [
	  { id: 'team-disabled', name: 'Archived', status: 'disabled', member_count: 0, created_at: '2026-08-11T01:00:00Z' },
	  { id: 'team-active', name: 'Platform', status: 'active', member_count: 1, created_at: '2026-08-11T01:00:00Z' },
	], pagination: { has_more: false } })
	client.listAccounts = vi.fn().mockResolvedValue({ data: [
	  { id: 'employee-1', email: 'member@example.internal', role: 'employee', status: 'active', team_ids: ['team-active'], created_at: '2026-08-11T01:00:00Z' },
	  { id: 'admin-1', email: 'admin@example.internal', role: 'system_administrator', status: 'active', team_ids: [], created_at: '2026-08-11T01:00:00Z' },
	  { id: 'employee-2', email: 'disabled@example.internal', role: 'employee', status: 'disabled', team_ids: ['team-disabled'], created_at: '2026-08-11T01:00:00Z' },
	], pagination: { has_more: false } })
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'People & teams' }))
	await screen.findByRole('table', { name: 'Accounts' })

	expect(screen.getByRole('button', { name: 'Recover member@example.internal' })).toBeInTheDocument()
	expect(screen.queryByRole('button', { name: 'Recover admin@example.internal' })).not.toBeInTheDocument()
	expect(screen.queryByRole('button', { name: 'Recover disabled@example.internal' })).not.toBeInTheDocument()
	await user.click(screen.getByRole('button', { name: 'Invite employee' }))
	expect(screen.getByRole('combobox', { name: 'Assigned team' })).toHaveValue('team-active')
	expect(screen.getByRole('combobox', { name: 'Assigned team' })).not.toHaveTextContent('Archived')
  })

  it('reauthenticates before retrying compromise recovery', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.issuePasswordReset = vi.fn().mockRejectedValueOnce({ code: 'REAUTHENTICATION_REQUIRED' }).mockResolvedValueOnce({ code: 'reset-once', email: 'member@example.internal', expires_at: '2026-08-12T12:00:00Z' })
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'People & teams' }))
	await screen.findByText('member@example.internal')
	await user.click(screen.getByRole('button', { name: 'Recover member@example.internal' }))
	await user.click(screen.getByRole('checkbox', { name: 'Manual identity verification completed' }))
	await user.click(screen.getByRole('checkbox', { name: 'Treat as credential compromise' }))
	await user.click(screen.getByRole('button', { name: 'Issue reset value' }))
	expect(await screen.findByRole('dialog', { name: 'Reauthenticate' })).toBeInTheDocument()
	await user.type(screen.getByLabelText('Current password'), 'current-password')
	await user.click(screen.getByRole('button', { name: 'Reauthenticate and continue' }))
	expect(await screen.findByRole('dialog', { name: 'New password reset value' })).toHaveTextContent('reset-once')
	expect(client.reauthenticate).toHaveBeenCalledWith('current-password')
  })

  it('creates and disables service accounts with explicit confirmation', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Service accounts' }))
	await screen.findByText('ci-agent')
	await user.click(screen.getByRole('button', { name: 'Create service account' }))
	await user.type(screen.getByRole('textbox', { name: 'Service account name' }), 'build-agent')
	await user.selectOptions(screen.getByRole('combobox', { name: 'Service account team' }), 'team-1')
	await user.selectOptions(screen.getByRole('combobox', { name: 'Responsible employee' }), 'employee-1')
	await user.click(screen.getByRole('button', { name: 'Create account' }))
	expect(client.createServiceAccount).toHaveBeenCalledWith('team-1', 'employee-1', 'build-agent')
	expect(await screen.findByRole('table', { name: 'Service accounts' })).toHaveTextContent('build-agent')

	await user.click(screen.getByRole('button', { name: 'Disable ci-agent' }))
	expect(client.disableServiceAccount).not.toHaveBeenCalled()
	await user.click(screen.getByRole('button', { name: 'Disable service account' }))
	expect(client.disableServiceAccount).toHaveBeenCalledWith('service-1')
  })

  it('limits service-account owners to active employees in the selected team', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.listTeams = vi.fn().mockResolvedValue({ data: [
	  { id: 'team-1', name: 'Platform', status: 'active', member_count: 1, created_at: '2026-08-11T01:00:00Z' },
	  { id: 'team-2', name: 'Data', status: 'active', member_count: 1, created_at: '2026-08-11T01:00:00Z' },
	], pagination: { has_more: false } })
	client.listAccounts = vi.fn().mockResolvedValue({ data: [
	  { id: 'employee-1', email: 'platform@example.internal', role: 'employee', status: 'active', team_ids: ['team-1'], created_at: '2026-08-11T01:00:00Z' },
	  { id: 'employee-2', email: 'data@example.internal', role: 'employee', status: 'active', team_ids: ['team-2'], created_at: '2026-08-11T01:00:00Z' },
	], pagination: { has_more: false } })
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Service accounts' }))
	await screen.findByText('ci-agent')
	await user.click(screen.getByRole('button', { name: 'Create service account' }))

	expect(screen.getByRole('combobox', { name: 'Responsible employee' })).toHaveTextContent('platform@example.internal')
	expect(screen.getByRole('combobox', { name: 'Responsible employee' })).not.toHaveTextContent('data@example.internal')
	await user.selectOptions(screen.getByRole('combobox', { name: 'Service account team' }), 'team-2')
	expect(screen.getByRole('combobox', { name: 'Responsible employee' })).toHaveValue('employee-2')
	expect(screen.getByRole('combobox', { name: 'Responsible employee' })).toHaveTextContent('data@example.internal')
	expect(screen.getByRole('combobox', { name: 'Responsible employee' })).not.toHaveTextContent('platform@example.internal')
  })

  it('requires explicit confirmation before disabling a team', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'People & teams' }))
	await screen.findByRole('table', { name: 'Teams' })

	await user.click(screen.getByRole('button', { name: 'Disable Platform' }))
	expect(client.disableTeam).not.toHaveBeenCalled()
	expect(screen.getByRole('dialog', { name: 'Disable team' })).toBeInTheDocument()
	await user.click(screen.getByRole('button', { name: 'Disable team' }))
	expect(client.disableTeam).toHaveBeenCalledWith('team-1')
  })

  it('confirms role changes, membership removal, and account disablement', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'People & teams' }))
	await screen.findByText('member@example.internal')
	await user.click(screen.getByRole('button', { name: 'Manage access for member@example.internal' }))

	await user.selectOptions(screen.getByLabelText('Role'), 'team_administrator')
	await user.click(screen.getByRole('button', { name: 'Apply role' }))
	expect(client.updateAccount).not.toHaveBeenCalled()
	await user.click(screen.getByRole('button', { name: 'Apply role change' }))
	expect(client.updateAccount).toHaveBeenCalledWith('employee-1', { role: 'team_administrator', confirmed: true })

	await user.click(screen.getByRole('button', { name: 'Remove membership' }))
	expect(client.removeMember).not.toHaveBeenCalled()
	await user.click(screen.getByRole('button', { name: 'Confirm removal' }))
	expect(client.removeMember).toHaveBeenCalledWith('team-1', 'employee-1')

	await user.click(screen.getByRole('button', { name: 'Disable account' }))
	expect(client.updateAccount).toHaveBeenCalledTimes(1)
	await user.click(within(screen.getByRole('dialog', { name: 'Disable account' })).getByRole('button', { name: 'Disable account' }))
	expect(client.updateAccount).toHaveBeenLastCalledWith('employee-1', { status: 'disabled', confirmed: true })
  })

  it('updates an account company email and reflects the saved value locally', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'People & teams' }))
	await screen.findByText('member@example.internal')
	await user.click(screen.getByRole('button', { name: 'Manage access for member@example.internal' }))

	const email = screen.getByRole('textbox', { name: 'Company email' })
	await user.clear(email)
	await user.type(email, 'renamed@example.internal')
	await user.click(screen.getByRole('button', { name: 'Save email' }))

	await waitFor(() => expect(client.updateAccount).toHaveBeenCalledWith('employee-1', { email: 'renamed@example.internal' }))
	expect(screen.getByRole('table', { name: 'Accounts' })).toHaveTextContent('renamed@example.internal')
  })

  it('keeps email editing available after an update failure', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.updateAccount = vi.fn().mockRejectedValue(new Error('temporary'))
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'People & teams' }))
	await screen.findByText('member@example.internal')
	await user.click(screen.getByRole('button', { name: 'Manage access for member@example.internal' }))
	await user.click(screen.getByRole('button', { name: 'Save email' }))

	expect(await screen.findByRole('alert')).toHaveTextContent('Unable to update this email.')
	expect(screen.getByRole('button', { name: 'Save email' })).toBeEnabled()
  })

  it('creates a group key and saves the model and retention policies after confirmation', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Service accounts' }))
	await screen.findByText('ci-agent')
	await user.click(screen.getByRole('button', { name: 'Manage keys for ci-agent' }))
	await user.click(screen.getByRole('button', { name: 'Create group key' }))
	await user.type(screen.getByRole('textbox', { name: 'Group key name' }), 'deploy')
	await user.click(screen.getByRole('button', { name: 'Create key' }))
	expect(await screen.findByRole('dialog', { name: 'New group key' })).toHaveTextContent('nap_group_once')

	await user.click(screen.getByRole('link', { name: 'Model policy' }))
	expect(await screen.findByRole('table', { name: 'Global model allowlist' })).toHaveTextContent('gpt-test')
	await user.click(screen.getByRole('button', { name: 'Save model policy' }))
	expect(screen.getByRole('dialog', { name: 'Confirm model policy' })).toBeInTheDocument()
	await user.click(screen.getByRole('button', { name: 'Confirm model policy change' }))
	expect(client.replaceModelAllowlist).toHaveBeenCalled()

	await user.click(screen.getByRole('link', { name: 'Retention' }))
	expect(await screen.findByRole('spinbutton', { name: 'Raw content retention days' })).toHaveValue(7)
	await user.click(screen.getByRole('button', { name: 'Save retention policy' }))
	await user.click(screen.getByRole('button', { name: 'Confirm retention change' }))
	expect(client.replaceRetentionPolicy).toHaveBeenCalledWith(7, true)
  })

  it('loads additional group-key pages without replacing earlier keys', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.listServiceKeys = vi.fn()
		.mockResolvedValueOnce({ data: [{ id: 'key-1', kind: 'service', service_account_id: 'service-1', team_id: 'team-1', name: 'primary', prefix: 'nap_primary1', status: 'active', created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: true, next_cursor: 'keys-2' } })
		.mockResolvedValueOnce({ data: [{ id: 'key-2', kind: 'service', service_account_id: 'service-1', team_id: 'team-1', name: 'retired', prefix: 'nap_retired1', status: 'revoked', created_at: '2026-08-10T01:00:00Z' }], pagination: { has_more: false } })
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Service accounts' }))
	await user.click(await screen.findByRole('button', { name: 'Manage keys for ci-agent' }))
	expect(await screen.findByRole('table', { name: 'Group keys for ci-agent' })).toHaveTextContent('primary')
	await user.click(screen.getByRole('button', { name: 'Load more group keys' }))
	await waitFor(() => expect(client.listServiceKeys).toHaveBeenLastCalledWith('service-1', { cursor: 'keys-2' }))
	expect(screen.getByRole('table', { name: 'Group keys for ci-agent' })).toHaveTextContent('retired')
  })

  it('clears the previous service account keys before loading another account', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.listServiceAccounts = vi.fn().mockResolvedValue({ data: [
	  { id: 'service-1', team_id: 'team-1', responsible_account_id: 'employee-1', name: 'ci-agent', status: 'active', created_at: '2026-08-11T01:00:00Z' },
	  { id: 'service-2', team_id: 'team-1', responsible_account_id: 'employee-1', name: 'release-agent', status: 'active', created_at: '2026-08-10T01:00:00Z' },
	], pagination: { has_more: false } })
	client.listServiceKeys = vi.fn()
	  .mockResolvedValueOnce({ data: [{ id: 'key-1', kind: 'service', service_account_id: 'service-1', team_id: 'team-1', name: 'ci-only', prefix: 'nap_ci_only', status: 'active', created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: false } })
	  .mockResolvedValueOnce({ data: [], pagination: { has_more: false } })
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Service accounts' }))
	await user.click(await screen.findByRole('button', { name: 'Manage keys for ci-agent' }))
	await screen.findByText('ci-only')
	await user.click(screen.getByRole('button', { name: 'Close' }))
	await user.click(screen.getByRole('button', { name: 'Manage keys for release-agent' }))
	await waitFor(() => expect(screen.queryByText('ci-only')).not.toBeInTheDocument())
	expect(screen.getByRole('table', { name: 'Group keys for release-agent' })).toHaveTextContent('No group keys yet.')
  })

  it('adds the first model to an empty global allowlist before confirmed save', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.getModelAllowlist = vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } })
	client.replaceModelAllowlist = vi.fn().mockImplementation(async (models) => ({ data: models, pagination: { has_more: false } }))
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Model policy' }))
	await screen.findByRole('table', { name: 'Global model allowlist' })

	await user.type(screen.getByRole('textbox', { name: 'Model ID' }), 'gpt-internal')
	await user.click(screen.getByRole('button', { name: 'Add model' }))
	expect(screen.getByRole('table', { name: 'Global model allowlist' })).toHaveTextContent('gpt-internal')
	await user.click(screen.getByRole('button', { name: 'Save model policy' }))
	await user.click(screen.getByRole('button', { name: 'Confirm model policy change' }))
	expect(client.replaceModelAllowlist).toHaveBeenCalledWith([
	  expect.objectContaining({ id: 'gpt-internal', status: 'allowed' }),
	], true)
  })

  it('saves a complete non-negative decimal model price tuple', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Model policy' }))
	await screen.findByRole('table', { name: 'Global model allowlist' })
	await user.type(screen.getByRole('textbox', { name: 'Input unit price for gpt-test' }), '0.001')
	await user.type(screen.getByRole('textbox', { name: 'Output unit price for gpt-test' }), '0.002')
	await user.type(screen.getByRole('textbox', { name: 'Price version for gpt-test' }), '2026-09')
	await user.click(screen.getByRole('button', { name: 'Save model policy' }))
	await user.click(screen.getByRole('button', { name: 'Confirm model policy change' }))

	expect(client.replaceModelAllowlist).toHaveBeenCalledWith([
	  expect.objectContaining({ id: 'gpt-test', input_unit_price: '0.001', output_unit_price: '0.002', price_version: '2026-09' }),
	], true)
  })

  it.each([
	['partial price tuple', '0.001', '', '2026-09'],
	['negative price', '-1', '0.002', '2026-09'],
	['non-decimal price', '1e3', '0.002', '2026-09'],
	['blank version', '0.001', '0.002', '   '],
  ])('rejects an invalid model price tuple: %s', async (_label, inputPrice, outputPrice, version) => {
	const user = userEvent.setup()
	const client = adminClient()
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Model policy' }))
	await screen.findByRole('table', { name: 'Global model allowlist' })
	await user.type(screen.getByRole('textbox', { name: 'Input unit price for gpt-test' }), inputPrice)
	if (outputPrice) await user.type(screen.getByRole('textbox', { name: 'Output unit price for gpt-test' }), outputPrice)
	await user.type(screen.getByRole('textbox', { name: 'Price version for gpt-test' }), version)
	await user.click(screen.getByRole('button', { name: 'Save model policy' }))

	expect(await screen.findByRole('alert')).toHaveTextContent('Model pricing must use a complete non-negative decimal tuple with a non-blank version.')
	expect(client.replaceModelAllowlist).not.toHaveBeenCalled()
  })

  it('shows security events as an independent administrator workspace', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.listSecurityEvents = vi.fn().mockResolvedValue({ data: [{ id: 'security-1', event_type: 'login_lockout', actor_account_id: 'admin-1', target_account_id: 'employee-1', request_id: 'request-1', outcome: 'denied', occurred_at: '2026-08-14T09:00:00Z' }], pagination: { has_more: false } })
	render(<App role="system_administrator" adminClient={client} />)

	expect(screen.getByRole('navigation', { name: 'Primary navigation' })).toHaveTextContent('Security events')
	await user.click(screen.getByRole('link', { name: 'Security events' }))
	expect(await screen.findByRole('table', { name: 'Security events' })).toHaveTextContent('login_lockout')
	expect(client.listOperationalEvents).not.toHaveBeenCalled()
  })

  it('loads later account and team pages without replacing the first page', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.listAccounts = vi.fn()
	  .mockResolvedValueOnce({ data: [{ id: 'employee-1', email: 'first@example.internal', role: 'employee', status: 'active', team_ids: ['team-1'], created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: true, next_cursor: 'accounts-2' } })
	  .mockResolvedValueOnce({ data: [{ id: 'employee-2', email: 'second@example.internal', role: 'employee', status: 'active', team_ids: ['team-2'], created_at: '2026-08-10T01:00:00Z' }], pagination: { has_more: false } })
	client.listTeams = vi.fn()
	  .mockResolvedValueOnce({ data: [{ id: 'team-1', name: 'Platform', status: 'active', member_count: 1, created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: true, next_cursor: 'teams-2' } })
	  .mockResolvedValueOnce({ data: [{ id: 'team-2', name: 'Data', status: 'active', member_count: 1, created_at: '2026-08-10T01:00:00Z' }], pagination: { has_more: false } })
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'People & teams' }))
	await screen.findByText('first@example.internal')

	await user.click(screen.getByRole('button', { name: 'Load more accounts' }))
	expect(await screen.findByText('second@example.internal')).toBeInTheDocument()
	expect(screen.getByText('first@example.internal')).toBeInTheDocument()
	expect(client.listAccounts).toHaveBeenLastCalledWith({ cursor: 'accounts-2' })

	await user.click(screen.getByRole('button', { name: 'Load more teams' }))
	expect(await screen.findByText('Data')).toBeInTheDocument()
	expect(screen.getByText('Platform')).toBeInTheDocument()
	expect(client.listTeams).toHaveBeenLastCalledWith({ cursor: 'teams-2' })
  })

  it('loads later service-account pages with the service cursor', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.listServiceAccounts = vi.fn()
	  .mockResolvedValueOnce({ data: [{ id: 'service-1', team_id: 'team-1', responsible_account_id: 'employee-1', name: 'first-agent', status: 'active', created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: true, next_cursor: 'services-2' } })
	  .mockResolvedValueOnce({ data: [{ id: 'service-2', team_id: 'team-1', responsible_account_id: 'employee-1', name: 'second-agent', status: 'active', created_at: '2026-08-10T01:00:00Z' }], pagination: { has_more: false } })
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Service accounts' }))
	await screen.findByText('first-agent')

	await user.click(screen.getByRole('button', { name: 'Load more service accounts' }))
	expect(await screen.findByText('second-agent')).toBeInTheDocument()
	expect(screen.getByText('first-agent')).toBeInTheDocument()
	expect(client.listServiceAccounts).toHaveBeenLastCalledWith({ cursor: 'services-2' })
  })

  it('loads every active team and employee page used by service-account creation', async () => {
	const user = userEvent.setup()
	const client = adminClient()
	client.listTeams = vi.fn()
	  .mockResolvedValueOnce({ data: [{ id: 'team-1', name: 'Platform', status: 'active', member_count: 1, created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: true, next_cursor: 'teams-2' } })
	  .mockResolvedValueOnce({ data: [{ id: 'team-2', name: 'Data', status: 'active', member_count: 1, created_at: '2026-08-10T01:00:00Z' }], pagination: { has_more: false } })
	client.listAccounts = vi.fn()
	  .mockResolvedValueOnce({ data: [{ id: 'employee-1', email: 'platform@example.internal', role: 'employee', status: 'active', team_ids: ['team-1'], created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: true, next_cursor: 'employees-2' } })
	  .mockResolvedValueOnce({ data: [{ id: 'employee-2', email: 'data@example.internal', role: 'employee', status: 'active', team_ids: ['team-2'], created_at: '2026-08-10T01:00:00Z' }], pagination: { has_more: false } })
	render(<App role="system_administrator" adminClient={client} />)
	await user.click(screen.getByRole('link', { name: 'Service accounts' }))
	await screen.findByText('ci-agent')
	await user.click(screen.getByRole('button', { name: 'Create service account' }))

	await user.selectOptions(screen.getByRole('combobox', { name: 'Service account team' }), 'team-2')
	expect(screen.getByRole('combobox', { name: 'Responsible employee' })).toHaveTextContent('data@example.internal')
	expect(client.listTeams).toHaveBeenLastCalledWith({ status: 'active', cursor: 'teams-2' })
	expect(client.listAccounts).toHaveBeenLastCalledWith({ status: 'active', role: 'employee', cursor: 'employees-2' })
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

function adminClient(): AdminPortalClient {
  return {
	listAccounts: vi.fn().mockResolvedValue({ data: [{ id: 'employee-1', email: 'member@example.internal', role: 'employee', status: 'active', team_ids: ['team-1'], created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: false } }),
	listTeams: vi.fn().mockResolvedValue({ data: [{ id: 'team-1', name: 'Platform', status: 'active', member_count: 1, created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: false } }),
	createTeam: vi.fn().mockResolvedValue({ id: 'team-new', name: 'Internal Test', status: 'active', member_count: 0, created_at: '2026-10-09T01:00:00Z' }),
	disableTeam: vi.fn().mockResolvedValue(undefined),
	invite: vi.fn().mockResolvedValue({ invitation: { account_id: 'employee-2', email: 'new@example.internal', team_id: 'team-1', status: 'pending', expires_at: '2026-08-12T12:00:00Z', created_at: '2026-08-11T12:00:00Z' }, activation_code: 'activation-once' }),
	updateAccount: vi.fn().mockResolvedValue(undefined), addMember: vi.fn().mockResolvedValue(undefined), removeMember: vi.fn().mockResolvedValue(undefined),
	listServiceAccounts: vi.fn().mockResolvedValue({ data: [{ id: 'service-1', team_id: 'team-1', responsible_account_id: 'employee-1', name: 'ci-agent', status: 'active', created_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: false } }),
	createServiceAccount: vi.fn().mockResolvedValue({ id: 'service-2', team_id: 'team-1', responsible_account_id: 'employee-1', name: 'build-agent', status: 'active', created_at: '2026-08-11T01:00:00Z' }),
	disableServiceAccount: vi.fn().mockResolvedValue(undefined),
	listServiceKeys: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
	createServiceKey: vi.fn().mockResolvedValue({ key: { id: 'key-1', kind: 'service', service_account_id: 'service-1', team_id: 'team-1', name: 'deploy', prefix: 'nap_12345678', status: 'active', created_at: '2026-08-11T01:00:00Z' }, credential: { value: 'nap_group_once' } }),
	rotateServiceKey: vi.fn(), revokeServiceKey: vi.fn().mockResolvedValue(undefined),
	getModelAllowlist: vi.fn().mockResolvedValue({ data: [{ id: 'gpt-test', status: 'allowed', updated_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: false } }),
	replaceModelAllowlist: vi.fn().mockResolvedValue({ data: [{ id: 'gpt-test', status: 'allowed', updated_at: '2026-08-11T01:00:00Z' }], pagination: { has_more: false } }),
	getRetentionPolicy: vi.fn().mockResolvedValue({ days: 7, maximum_days: 30, updated_at: '2026-08-11T01:00:00Z' }),
	replaceRetentionPolicy: vi.fn().mockResolvedValue({ days: 7, maximum_days: 30, updated_at: '2026-08-11T01:00:00Z' }),
	issuePasswordReset: vi.fn().mockResolvedValue({ code: 'reset-once', email: 'member@example.internal', expires_at: '2026-08-12T12:00:00Z' }),
	listAudits: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
	inspectAudit: vi.fn(),
	getOperationsHealth: vi.fn().mockResolvedValue({ state: 'healthy', components: [], checked_at: '2026-08-14T09:00:00Z' }),
	listOperationalEvents: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
	listSecurityEvents: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
	reauthenticate: vi.fn().mockResolvedValue(undefined),
  }
}
