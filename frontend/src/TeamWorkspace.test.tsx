import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { TeamPortalClient } from './team-api'
import { TeamWorkspace } from './TeamWorkspace'

afterEach(cleanup)

describe('TeamWorkspace', () => {
  it('recovers from a failed section load when a later section succeeds', async () => {
    const client = {
      listTeamMembers: vi.fn()
        .mockRejectedValueOnce(new Error('synthetic member failure'))
        .mockResolvedValue({ data: [], pagination: { has_more: false } }),
      listTeamUsage: vi.fn().mockResolvedValue({
        data: [],
        pagination: { has_more: false },
        aggregate: { request_count: 0, reported_usage_count: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0 },
      }),
    } as unknown as TeamPortalClient
    const view = render(<TeamWorkspace section="Team members" teamID="team-1" client={client} />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load this team workspace right now.')

    view.rerender(<TeamWorkspace section="Team usage" teamID="team-1" client={client} />)

    expect(await screen.findByRole('table', { name: 'Team usage records' })).toBeInTheDocument()
    expect(screen.queryByText('Unable to load this team workspace right now.')).not.toBeInTheDocument()
  })
})
