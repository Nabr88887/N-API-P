import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { AdminPortalClient } from './admin-api'
import { OperationsWorkspace } from './OperationsWorkspace'

describe('OperationsWorkspace', () => {
  it('renders recent allowlisted events without raw server detail text', async () => {
    const client = {
      listOperationalEvents: vi.fn().mockResolvedValue({
        data: [
          { id: 'event-1', event_type: 'raw_deletion_overdue', severity: 'critical', detail_code: 'DROP TABLE audit_raw_content', occurred_at: '2026-08-14T09:00:00Z' },
          { id: 'event-2', event_type: 'unknown_internal_fault', severity: 'critical', detail_code: 'C:\\secrets\\audit.key', occurred_at: '2026-08-14T09:01:00Z' },
        ],
        pagination: { has_more: false },
      }),
    } as unknown as AdminPortalClient

    render(<OperationsWorkspace client={client} />)

    expect(await screen.findByRole('table', { name: 'Recent operational events' })).toHaveTextContent('Raw content deletion overdue')
    expect(screen.getByRole('table', { name: 'Recent operational events' })).toHaveTextContent('Critical')
    expect(screen.queryByText(/DROP TABLE|secrets|unknown_internal_fault/)).not.toBeInTheDocument()
  })

  it('loads the next bounded event page without replacing earlier events', async () => {
    const user = userEvent.setup()
    const client = {
      listOperationalEvents: vi.fn()
        .mockResolvedValueOnce({ data: [{ id: 'event-1', event_type: 'audit_unavailable', severity: 'critical', occurred_at: '2026-08-14T09:00:00Z' }], pagination: { has_more: true, next_cursor: 'events-2' } })
        .mockResolvedValueOnce({ data: [{ id: 'event-2', event_type: 'required_key_failure', severity: 'recovery', occurred_at: '2026-08-14T08:00:00Z' }], pagination: { has_more: false } }),
    } as unknown as AdminPortalClient

    render(<OperationsWorkspace client={client} />)
    await screen.findByText('Audit persistence unavailable')
    await user.click(screen.getByRole('button', { name: 'Load more events' }))

    expect(await screen.findByText('Required audit key unavailable')).toBeInTheDocument()
    expect(screen.getByText('Audit persistence unavailable')).toBeInTheDocument()
    expect(client.listOperationalEvents).toHaveBeenLastCalledWith({ cursor: 'events-2' })
  })

  it('stops loading when an operational events cursor repeats', async () => {
    const user = userEvent.setup()
    const client = {
      listOperationalEvents: vi.fn()
        .mockResolvedValueOnce({ data: [{ id: 'event-1', event_type: 'audit_unavailable', severity: 'critical', occurred_at: '2026-08-14T09:00:00Z' }], pagination: { has_more: true, next_cursor: 'events-2' } })
        .mockResolvedValueOnce({ data: [{ id: 'event-2', event_type: 'required_key_failure', severity: 'recovery', occurred_at: '2026-08-14T08:00:00Z' }], pagination: { has_more: true, next_cursor: 'events-2' } }),
    } as unknown as AdminPortalClient

    render(<OperationsWorkspace client={client} />)
    await user.click(await screen.findByRole('button', { name: 'Load more events' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load more operational events.')
    expect(screen.queryByRole('button', { name: 'Load more events' })).not.toBeInTheDocument()
    expect(client.listOperationalEvents).toHaveBeenCalledTimes(2)
  })
})
