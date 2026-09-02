import { useCallback, useEffect, useState, type FormEvent } from 'react'

import { App } from './App'
import { createPortalClient, type PortalClient, type PortalIdentity } from './portal-api'

export type { PortalClient } from './portal-api'

type AnonymousMode = 'sign-in' | 'activate' | 'reset'

export function Portal({ client: injectedClient }: { client?: PortalClient }) {
  const [client] = useState(() => injectedClient ?? createPortalClient())
  const [identity, setIdentity] = useState<PortalIdentity | null>(null)
  const [loading, setLoading] = useState(true)
  const [mode, setMode] = useState<AnonymousMode>('sign-in')
  const [error, setError] = useState('')

  const refreshSession = useCallback(async () => {
    setLoading(true)
    try {
      setIdentity(await client.me())
      setError('')
    } catch {
      setIdentity(null)
    } finally {
      setLoading(false)
    }
  }, [client])

  const logout = useCallback(async () => {
    await client.logout()
    setIdentity(null)
    setMode('sign-in')
    setError('')
  }, [client])

  useEffect(() => {
    let active = true
    void client.me().then((nextIdentity) => {
      if (active) {
        setIdentity(nextIdentity)
        setError('')
      }
    }).catch(() => {
      if (active) setIdentity(null)
    }).finally(() => {
      if (active) setLoading(false)
    })
    return () => { active = false }
  }, [client])

  if (loading) return <main className="portal-state"><p>Loading session…</p></main>
  if (identity) return <App role={identity.role} teamID={identity.team_ids?.[0] ?? ''} teamIDs={identity.team_ids} identityEmail={identity.email} onLogout={logout} />

  return (
    <main className="portal-state">
      <section className="portal-panel" aria-labelledby="portal-title">
        <p className="section-kicker">N-API-P</p>
        <h1 id="portal-title">{mode === 'sign-in' ? 'Sign in' : mode === 'activate' ? 'Activate account' : 'Reset password'}</h1>
        {error && <p className="error-state" role="alert">{error}</p>}
        {mode === 'sign-in' && <SignInForm client={client} onComplete={refreshSession} onError={setError} />}
        {mode === 'activate' && <ActivationForm client={client} onModeChange={setMode} onError={setError} />}
        {mode === 'reset' && <ResetForm client={client} onModeChange={setMode} onError={setError} />}
        <div className="portal-actions">
          {mode !== 'sign-in' && <button className="button button-secondary" type="button" onClick={() => { setError(''); setMode('sign-in') }}>Sign in</button>}
          {mode !== 'activate' && <button className="button button-secondary" type="button" onClick={() => { setError(''); setMode('activate') }}>Activate account</button>}
          {mode !== 'reset' && <button className="button button-secondary" type="button" onClick={() => { setError(''); setMode('reset') }}>Reset password</button>}
        </div>
      </section>
    </main>
  )
}

function SignInForm({ client, onComplete, onError }: { client: PortalClient; onComplete: () => Promise<void>; onError: (message: string) => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try { await client.login(email, password); await onComplete() } catch { onError('Unable to sign in.') }
  }
  return <form className="dialog-form" onSubmit={submit}><label className="field-label" htmlFor="portal-email">Company email</label><input id="portal-email" type="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} required /><label className="field-label" htmlFor="portal-password">Password</label><input id="portal-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><button className="button button-primary" type="submit">Continue</button></form>
}

function ActivationForm({ client, onModeChange, onError }: { client: PortalClient; onModeChange: (mode: AnonymousMode) => void; onError: (message: string) => void }) {
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try { await client.activate(email, code, password); onModeChange('sign-in') } catch { onError('Unable to activate this account.') }
  }
  return <form className="dialog-form" onSubmit={submit}><label className="field-label" htmlFor="activation-email">Company email</label><input id="activation-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /><label className="field-label" htmlFor="activation-code">Activation code</label><input id="activation-code" value={code} onChange={(event) => setCode(event.target.value)} required /><label className="field-label" htmlFor="activation-password">New password</label><input id="activation-password" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><button className="button button-primary" type="submit">Continue</button></form>
}

function ResetForm({ client, onModeChange, onError }: { client: PortalClient; onModeChange: (mode: AnonymousMode) => void; onError: (message: string) => void }) {
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try { await client.resetPassword(email, code, password); onModeChange('sign-in') } catch { onError('Unable to reset this password.') }
  }
  return <form className="dialog-form" onSubmit={submit}><label className="field-label" htmlFor="reset-email">Company email</label><input id="reset-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /><label className="field-label" htmlFor="reset-code">Reset code</label><input id="reset-code" value={code} onChange={(event) => setCode(event.target.value)} required /><label className="field-label" htmlFor="reset-password">New password</label><input id="reset-password" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><button className="button button-primary" type="submit">Continue</button></form>
}
