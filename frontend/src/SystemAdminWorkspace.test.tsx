import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AdminAPIError, type AdminPortalClient } from './admin-api'
import { SystemAdminWorkspace } from './SystemAdminWorkspace'

afterEach(cleanup)

describe('SystemAdminWorkspace', () => {
  it('recovers from a failed section load when a later section succeeds', async () => {
    const client = {
      listAccounts: vi.fn().mockRejectedValue(new Error('synthetic account failure')),
      listTeams: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
      getRetentionPolicy: vi.fn().mockResolvedValue({ days: 7, maximum_days: 30, updated_at: '2026-08-11T01:00:00Z' }),
    } as unknown as AdminPortalClient
    const view = render(<SystemAdminWorkspace section="People & teams" client={client} />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load this workspace right now.')

    view.rerender(<SystemAdminWorkspace section="Retention" client={client} />)

    expect(await screen.findByRole('heading', { name: 'Retention' })).toBeInTheDocument()
    expect(screen.queryByText('Unable to load this workspace right now.')).not.toBeInTheDocument()
  })

  it('keeps membership controls and team counts synchronized after changes', async () => {
    const user = userEvent.setup()
    const client = {
      listAccounts: vi.fn().mockResolvedValue({
        data: [{ id: 'employee-1', email: 'member@example.internal', role: 'employee', status: 'active', team_ids: [], created_at: '2026-08-11T01:00:00Z' }],
        pagination: { has_more: false },
      }),
      listTeams: vi.fn().mockResolvedValue({
        data: [{ id: 'team-1', name: 'Platform', status: 'active', member_count: 0, created_at: '2026-08-11T01:00:00Z' }],
        pagination: { has_more: false },
      }),
      addMember: vi.fn().mockResolvedValue(undefined),
      removeMember: vi.fn().mockResolvedValue(undefined),
    } as unknown as AdminPortalClient
    render(<SystemAdminWorkspace section="People & teams" client={client} />)
    await user.click(await screen.findByRole('button', { name: 'Manage access for member@example.internal' }))

    const add = screen.getByRole('button', { name: 'Add membership' })
    const remove = screen.getByRole('button', { name: 'Remove membership' })
    await user.click(add)

    await waitFor(() => expect(client.addMember).toHaveBeenCalledWith('team-1', 'employee-1'))
    expect(add).toBeDisabled()
    expect(remove).toBeEnabled()
    expect(within(screen.getByRole('table', { name: 'Teams' })).getByText('Platform').closest('tr')).toHaveTextContent('1')

    await user.click(remove)
    await user.click(within(screen.getByRole('dialog', { name: 'Remove membership' })).getByRole('button', { name: 'Confirm removal' }))

    await waitFor(() => expect(client.removeMember).toHaveBeenCalledWith('team-1', 'employee-1'))
    expect(add).toBeEnabled()
    expect(remove).toBeDisabled()
    expect(within(screen.getByRole('table', { name: 'Teams' })).getByText('Platform').closest('tr')).toHaveTextContent('0')
  })

  it('reauthenticates and retries a rejected role change', async () => {
		const user = userEvent.setup()
		const client = {
			listAccounts: vi.fn().mockResolvedValue({
				data: [{ id: 'employee-1', email: 'member@example.internal', role: 'employee', status: 'active', team_ids: [], created_at: '2026-08-11T01:00:00Z' }],
				pagination: { has_more: false },
			}),
			listTeams: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
			updateAccount: vi.fn().mockRejectedValueOnce(new AdminAPIError('REAUTHENTICATION_REQUIRED')).mockResolvedValueOnce(undefined),
			reauthenticate: vi.fn().mockResolvedValue(undefined),
		} as unknown as AdminPortalClient
		render(<SystemAdminWorkspace section="People & teams" client={client} />)
		await user.click(await screen.findByRole('button', { name: 'Manage access for member@example.internal' }))
		await user.selectOptions(screen.getByLabelText('Role'), 'system_administrator')
		await user.click(screen.getByRole('button', { name: 'Apply role' }))
		await user.click(within(screen.getByRole('dialog', { name: 'Confirm role change' })).getByRole('button', { name: 'Apply role change' }))

		const reauthentication = await screen.findByRole('dialog', { name: 'Reauthenticate' })
		await user.type(within(reauthentication).getByLabelText('Current password'), 'current-password')
		await user.click(within(reauthentication).getByRole('button', { name: 'Reauthenticate and continue' }))

		await waitFor(() => expect(client.updateAccount).toHaveBeenCalledTimes(2))
		expect(client.reauthenticate).toHaveBeenCalledWith('current-password')
		expect(client.updateAccount).toHaveBeenLastCalledWith('employee-1', { role: 'system_administrator', confirmed: true })
	})

	it('distinguishes a failed retried role change from failed reauthentication', async () => {
		const user = userEvent.setup()
		const client = {
			listAccounts: vi.fn().mockResolvedValue({
				data: [{ id: 'employee-1', email: 'member@example.internal', role: 'employee', status: 'active', team_ids: [], created_at: '2026-08-11T01:00:00Z' }],
				pagination: { has_more: false },
			}),
			listTeams: vi.fn().mockResolvedValue({ data: [], pagination: { has_more: false } }),
			updateAccount: vi.fn().mockRejectedValueOnce(new AdminAPIError('REAUTHENTICATION_REQUIRED')).mockRejectedValueOnce(new AdminAPIError('INTERNAL_ERROR')),
			reauthenticate: vi.fn().mockResolvedValue(undefined),
		} as unknown as AdminPortalClient
		render(<SystemAdminWorkspace section="People & teams" client={client} />)
		await user.click(await screen.findByRole('button', { name: 'Manage access for member@example.internal' }))
		await user.selectOptions(screen.getByLabelText('Role'), 'system_administrator')
		await user.click(screen.getByRole('button', { name: 'Apply role' }))
		await user.click(within(screen.getByRole('dialog', { name: 'Confirm role change' })).getByRole('button', { name: 'Apply role change' }))

		const reauthentication = await screen.findByRole('dialog', { name: 'Reauthenticate' })
		await user.type(within(reauthentication).getByLabelText('Current password'), 'current-password')
		await user.click(within(reauthentication).getByRole('button', { name: 'Reauthenticate and continue' }))

		expect(await screen.findByText('Unable to update this role.')).toBeInTheDocument()
		expect(screen.queryByText('Reauthentication failed.')).not.toBeInTheDocument()
	})
})
