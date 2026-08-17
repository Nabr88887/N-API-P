let csrfToken = ''

export function currentCSRFToken(): string {
  return csrfToken
}

export function rememberCSRFToken(value: string | null): void {
  if (value) csrfToken = value
}
