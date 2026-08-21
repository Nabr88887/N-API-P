let csrfToken = ''

const csrfCookieName = '__Host-n-api-p-csrf'

export function currentCSRFToken(): string {
  return csrfToken || readCSRFCookie()
}

export function rememberCSRFToken(value: string | null): void {
  csrfToken = value ?? ''
}

function readCSRFCookie(): string {
  if (typeof document === 'undefined') return ''
  for (const part of document.cookie.split(';')) {
    const separator = part.indexOf('=')
    if (separator < 0 || part.slice(0, separator).trim() !== csrfCookieName) continue
    try {
      return decodeURIComponent(part.slice(separator + 1))
    } catch {
      return ''
    }
  }
  return ''
}
