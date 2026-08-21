import { afterEach, expect, it, vi } from 'vitest'

afterEach(() => {
  document.cookie = '__Host-n-api-p-csrf=; Max-Age=0; Path=/; Secure; SameSite=Strict'
})

it('restores CSRF evidence from the same-origin cookie after a page reload', async () => {
  document.cookie = '__Host-n-api-p-csrf=reload-csrf-token; Path=/; Secure; SameSite=Strict'
  vi.resetModules()

  const { currentCSRFToken } = await import('./portal-session')

  expect(currentCSRFToken()).toBe('reload-csrf-token')
})

it('prefers current response evidence and clears stale in-memory evidence', async () => {
  document.cookie = '__Host-n-api-p-csrf=cookie-csrf-token; Path=/; Secure; SameSite=Strict'
  vi.resetModules()
  const { currentCSRFToken, rememberCSRFToken } = await import('./portal-session')

  rememberCSRFToken('response-csrf-token')
  expect(currentCSRFToken()).toBe('response-csrf-token')

  rememberCSRFToken(null)
  expect(currentCSRFToken()).toBe('cookie-csrf-token')
})
