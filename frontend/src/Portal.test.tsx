import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

import { Portal, type PortalClient } from './Portal'

afterEach(cleanup)

it('bootstraps the workspace from the authenticated server session', async () => {
  const client = portalClient()
  render(<Portal client={client} />)

  expect(await screen.findByText('employee@example.internal')).toBeInTheDocument()
  expect(screen.getByRole('navigation', { name: 'Primary navigation' })).toHaveTextContent('My keys')
  expect(screen.queryByRole('link', { name: 'Service accounts' })).not.toBeInTheDocument()
  expect(client.me).toHaveBeenCalledOnce()
})

it('shows anonymous recovery modes and reboots the session after login', async () => {
  const user = userEvent.setup()
  const client = portalClient()
  client.me = vi.fn().mockRejectedValueOnce(new Error('AUTHENTICATION_REQUIRED')).mockResolvedValue({
    id: 'employee-1', email: 'employee@example.internal', role: 'employee', team_ids: ['team-1'],
  })
  render(<Portal client={client} />)

  await screen.findByRole('heading', { name: 'Sign in' })
  await user.click(screen.getByRole('button', { name: 'Activate account' }))
  expect(screen.getByRole('heading', { name: 'Activate account' })).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Reset password' }))
  expect(screen.getByRole('heading', { name: 'Reset password' })).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  await user.type(screen.getByLabelText('Company email'), 'employee@example.internal')
  await user.type(screen.getByLabelText('Password'), 'synthetic-password')
  await user.click(screen.getByRole('button', { name: 'Continue' }))

  await waitFor(() => expect(client.login).toHaveBeenCalledWith('employee@example.internal', 'synthetic-password'))
  expect(await screen.findByText('employee@example.internal')).toBeInTheDocument()
})

function portalClient(): PortalClient {
  return {
    me: vi.fn().mockResolvedValue({ id: 'employee-1', email: 'employee@example.internal', role: 'employee', team_ids: ['team-1'] }),
    login: vi.fn().mockResolvedValue(undefined),
    activate: vi.fn().mockResolvedValue(undefined),
    resetPassword: vi.fn().mockResolvedValue(undefined),
    logout: vi.fn().mockResolvedValue(undefined),
  }
}
