import { afterEach, describe, expect, it, vi } from 'vitest'

import { createEmployeePortalClient } from './employee-api'

afterEach(() => vi.unstubAllGlobals())

describe('employee portal API client', () => {
  it('keeps the CSRF token in memory and sends it only on state changes', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 204, headers: { 'X-CSRF-Token': 'csrf-memory-only' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ key: {}, credential: { value: 'nap_once' } }), { status: 201, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem')
    const client = createEmployeePortalClient()

    await client.login('employee@example.internal', 'correct-password')
    await client.createPersonalKey('laptop')

    const [path, init] = fetchMock.mock.calls.at(-1) as [string, RequestInit]
    expect(path).toBe('/api/v1/me/personal-keys')
    expect(init.credentials).toBe('same-origin')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('csrf-memory-only')
    expect(storageSpy).not.toHaveBeenCalled()
  })
})
