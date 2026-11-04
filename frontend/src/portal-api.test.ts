import { afterEach, expect, it, vi } from 'vitest'

import { createPortalClient } from './portal-api'

afterEach(() => {
  vi.restoreAllMocks()
})

it('classifies a transport failure as an unavailable portal', async () => {
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('failed to fetch'))

  await expect(createPortalClient().login('employee@example.internal', 'password'))
    .rejects.toEqual(expect.objectContaining({ code: 'PORTAL_UNAVAILABLE' }))
})

it('classifies a Vite HTML fallback instead of treating it as invalid credentials', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<!doctype html>', { status: 404, headers: { 'Content-Type': 'text/html' } }))
  const client = createPortalClient()

  await expect(client.login('employee@example.internal', 'password'))
    .rejects.toMatchObject({ code: 'PORTAL_UNAVAILABLE' })
})

it('classifies an HTML gateway error as an unavailable portal', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<!doctype html>', { status: 502, headers: { 'Content-Type': 'text/html' } }))

  await expect(createPortalClient().login('employee@example.internal', 'password'))
    .rejects.toMatchObject({ code: 'PORTAL_UNAVAILABLE' })
})
