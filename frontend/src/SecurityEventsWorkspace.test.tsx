import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'

import type { AdminPortalClient } from './admin-api'
import { SecurityEventsWorkspace } from './SecurityEventsWorkspace'

afterEach(cleanup)

it('renders content-free security metadata and loads later pages', async () => {
  const user = userEvent.setup()
  const client = {
    listSecurityEvents: vi.fn()
      .mockResolvedValueOnce({ data: [{ id: 'event-1', event_type: 'login_lockout', actor_account_id: 'admin-1', target_account_id: 'employee-1', request_id: 'request-1', outcome: 'denied', reason: 'must not render', detail_code: 'must_not_render', occurred_at: '2026-08-14T09:00:00Z' }], pagination: { has_more: true, next_cursor: 'events-2' } })
      .mockResolvedValueOnce({ data: [{ id: 'event-2', event_type: 'role_changed', actor_account_id: 'admin-1', target_account_id: 'employee-2', request_id: 'request-2', outcome: 'success', occurred_at: '2026-08-14T09:01:00Z' }], pagination: { has_more: false } }),
  } as unknown as AdminPortalClient

  render(<SecurityEventsWorkspace client={client} />)
  expect(await screen.findByRole('table', { name: 'Security events' })).toHaveTextContent('login_lockout')
  expect(screen.queryByText(/must not render|must_not_render/)).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Load more security events' }))
  expect(await screen.findByText('role_changed')).toBeInTheDocument()
  expect(client.listSecurityEvents).toHaveBeenLastCalledWith({ cursor: 'events-2' })
})

it('keeps a failed security event page retryable', async () => {
  const user = userEvent.setup()
  const client = {
    listSecurityEvents: vi.fn()
      .mockResolvedValueOnce({ data: [], pagination: { has_more: true, next_cursor: 'events-2' } })
      .mockRejectedValueOnce(new Error('temporary'))
      .mockResolvedValueOnce({ data: [], pagination: { has_more: false } }),
  } as unknown as AdminPortalClient

  render(<SecurityEventsWorkspace client={client} />)
  await screen.findByRole('table', { name: 'Security events' })
  await user.click(screen.getByRole('button', { name: 'Load more security events' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load more security events.')
  await user.click(screen.getByRole('button', { name: 'Load more security events' }))
  expect(client.listSecurityEvents).toHaveBeenCalledTimes(3)
})
