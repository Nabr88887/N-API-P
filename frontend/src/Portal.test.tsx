import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

import { Portal, type PortalClient } from './Portal'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

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

it('returns an expired admin session to sign-in and restores audit metadata after login', async () => {
  const user = userEvent.setup()
  const identity = { id: 'admin-1', email: 'admin@example.internal', role: 'system_administrator' as const, team_ids: [] }
  const responses = [
    new Response(JSON.stringify(identity), { status: 200 }),
    new Response(JSON.stringify({ state: 'healthy', components: [], checked_at: '2026-08-14T09:00:00Z' }), { status: 200 }),
    new Response(JSON.stringify({ error: { code: 'AUTHENTICATION_REQUIRED' } }), { status: 401 }),
    new Response(null, { status: 204 }),
    new Response(JSON.stringify(identity), { status: 200 }),
    new Response(JSON.stringify({ state: 'healthy', components: [], checked_at: '2026-08-14T09:00:00Z' }), { status: 200 }),
    new Response(JSON.stringify({ data: [{ id: 'audit-recovered', request_id: 'request-recovered', key_id: 'key-recovered', team_id: 'team-1', model_id: 'audit-recovered-model', capture_status: 'complete', outcome: 'success', observed_request_bytes: 1, observed_response_bytes: 2, created_at: '2026-08-14T01:00:00Z', updated_at: '2026-08-14T01:01:00Z' }], pagination: { has_more: false } }), { status: 200 }),
  ]
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => responses.shift() ?? new Response(null, { status: 500 }))
  render(<Portal />)

  expect(await screen.findByText('admin@example.internal')).toBeInTheDocument()
  await user.click(screen.getByRole('link', { name: 'Audit' }))
  expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument()

  await user.type(screen.getByLabelText('Company email'), 'admin@example.internal')
  await user.type(screen.getByLabelText('Password'), 'synthetic-password')
  await user.click(screen.getByRole('button', { name: 'Continue' }))

  expect(await screen.findByText('admin@example.internal')).toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Sign in' })).not.toBeInTheDocument()
  await user.click(screen.getByRole('link', { name: 'Audit' }))
  expect(await screen.findByText('audit-recovered-model')).toBeInTheDocument()
})

it('ends the server session and returns to sign in', async () => {
  const user = userEvent.setup()
  const client = portalClient()
  render(<Portal client={client} />)

  await screen.findByText('employee@example.internal')
  await user.click(screen.getByRole('button', { name: 'Open session details' }))
  await user.click(screen.getByRole('button', { name: 'Sign out' }))

  await waitFor(() => expect(client.logout).toHaveBeenCalledOnce())
  expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
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
