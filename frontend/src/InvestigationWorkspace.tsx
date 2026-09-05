import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { AdminAPIError, type AdminPortalClient, type InvestigationCase, type InvestigationDisposition, type InvestigationRawView, type InvestigationCandidate, type Pagination } from './admin-api'
import { ModalDialog } from './ModalDialog'
import { advanceCursor } from './pagination'

export function InvestigationWorkspace({ client }: { client: AdminPortalClient }) {
  const [cases, setCases] = useState<InvestigationCase[]>([])
  const [casePagination, setCasePagination] = useState<Pagination>({ has_more: false })
  const [casePageLoading, setCasePageLoading] = useState(false)
  const [selected, setSelected] = useState<InvestigationCase | null>(null)
  const [candidates, setCandidates] = useState<InvestigationCandidate[]>([])
  const [view, setView] = useState<InvestigationRawView | null>(null)
  const [grantExpiresAt, setGrantExpiresAt] = useState('')
  const [error, setError] = useState('')
  const [subject, setSubject] = useState('')
  const [concern, setConcern] = useState('')
  const [reason, setReason] = useState('')
  const [start, setStart] = useState('')
  const [end, setEnd] = useState('')
  const [disposition, setDisposition] = useState<InvestigationDisposition>('inconclusive')
  const [note, setNote] = useState('')
  const [createConfirmed, setCreateConfirmed] = useState(false)
  const [closeConfirmed, setCloseConfirmed] = useState(false)
  const [reauthOpen, setReauthOpen] = useState(false)
  const [reauthPassword, setReauthPassword] = useState('')
  const pendingSensitiveAction = useRef<null | (() => Promise<void>)>(null)
  const caseCursors = useRef(new Set<string>())
  const caseLoadRequest = useRef(0)
  const caseDetailRequest = useRef(0)
  const inspectRequest = useRef(0)

  const loadCases = useCallback(async () => {
    if (!client.listInvestigationCases) return
    const requestID = ++caseLoadRequest.current
    const cursors = new Set<string>()
    caseCursors.current = cursors
    try {
      const page = await client.listInvestigationCases()
      if (requestID !== caseLoadRequest.current) return
      const nextCursor = advanceCursor(page.pagination, cursors)
      setCases(page.data)
      setCasePagination({ ...page.pagination, next_cursor: nextCursor })
      setError('')
    } catch {
      if (requestID === caseLoadRequest.current) setError('Unable to load investigation cases.')
    }
  }, [client])
  useEffect(() => { const timer = window.setTimeout(() => { void loadCases() }, 0); return () => window.clearTimeout(timer) }, [loadCases])
  useEffect(() => {
    if (!grantExpiresAt) return
    const delay = Math.max(0, Date.parse(grantExpiresAt) - Date.now())
    if (!Number.isFinite(delay) || delay > 2_147_483_647) return
    const timer = window.setTimeout(() => { setGrantExpiresAt(''); inspectRequest.current += 1; setView(null) }, delay)
    return () => window.clearTimeout(timer)
  }, [grantExpiresAt])

  async function createCase() {
    if (!client.createInvestigationCase || !subject.trim() || !concern.trim() || !reason.trim() || !start || !end || !createConfirmed) return
    const action = async () => {
      const response = await client.createInvestigationCase!({ subject_identity_id: subject.trim(), policy_concern: concern.trim(), reason: reason.trim(), start_at: new Date(start).toISOString(), end_at: new Date(end).toISOString(), confirmed: true })
      const detailRequestID = ++caseDetailRequest.current
      inspectRequest.current += 1
      setCases((current) => [response.case, ...current]); setSelected(response.case); setView(null); setCandidates([]); setGrantExpiresAt(response.grant.expires_at); setSubject(''); setConcern(''); setReason(''); setStart(''); setEnd(''); setCreateConfirmed(false)
      if (client.listInvestigationCandidates) {
        const page = await client.listInvestigationCandidates(response.case.id)
        if (detailRequestID === caseDetailRequest.current) setCandidates(page.data)
      }
    }
    try { await action(); setError('') } catch (failure: unknown) {
      if (!deferForReauthentication(failure, action)) setError(investigationErrorMessage(failure, 'Unable to create or load this investigation case.'))
    }
  }
  async function openCase(item: InvestigationCase) {
    if (!client.listInvestigationCandidates) return
    const detailRequestID = ++caseDetailRequest.current
    inspectRequest.current += 1
    setSelected(item); setView(null); setCandidates([]); setGrantExpiresAt(''); setCloseConfirmed(false)
    try {
      const page = await client.listInvestigationCandidates(item.id)
      if (detailRequestID !== caseDetailRequest.current) return
      setCandidates(page.data); setError('')
    } catch {
      if (detailRequestID === caseDetailRequest.current) setError('Unable to open or authorize this investigation case.')
    }
  }
  async function loadMoreCases() {
    if (!client.listInvestigationCases || !casePagination.next_cursor || casePageLoading) return
    setCasePageLoading(true)
    setError('')
    try {
      const page = await client.listInvestigationCases({ cursor: casePagination.next_cursor })
      const nextCursor = advanceCursor(page.pagination, caseCursors.current)
      setCases((current) => [...current, ...page.data.filter((item) => !current.some((existing) => existing.id === item.id))])
      setCasePagination({ ...page.pagination, next_cursor: nextCursor })
    } catch (failure: unknown) {
      if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setCasePagination({ has_more: false })
      setError('Unable to load more investigation cases.')
    } finally {
      setCasePageLoading(false)
    }
  }
  async function renewGrant() {
    if (!selected || selected.status !== 'open' || !client.issueInvestigationGrant) return
    const action = async () => { const grant = await client.issueInvestigationGrant!(selected.id); setGrantExpiresAt(grant.expires_at) }
    try { await action(); setError('') } catch (failure: unknown) {
      if (!deferForReauthentication(failure, action)) setError('Unable to renew access to this investigation case.')
    }
  }
  async function inspect(candidate: InvestigationCandidate) {
    if (!selected || !client.viewInvestigationAudit) return
    const requestID = ++inspectRequest.current
    setView(null)
    try {
      const result = await client.viewInvestigationAudit(selected.id, candidate.audit_id)
      if (requestID !== inspectRequest.current) return
      setView(result); setError('')
    } catch {
      if (requestID === inspectRequest.current) setError('Unable to view this audit record.')
    }
  }
  async function closeCase() {
    if (!selected || !client.closeInvestigationCase || !closeConfirmed) return
    const action = async () => {
      await client.closeInvestigationCase!(selected.id, disposition, note)
      const closed = { ...selected, status: 'closed' as const, disposition, closure_note: note }
      caseDetailRequest.current += 1; inspectRequest.current += 1
      setSelected(closed); setCases((current) => current.map((item) => item.id === closed.id ? closed : item)); setView(null); setGrantExpiresAt(''); setNote(''); setCloseConfirmed(false)
    }
    try { await action(); setError('') } catch (failure: unknown) {
      if (!deferForReauthentication(failure, action)) setError('Unable to close this case.')
    }
  }

  function deferForReauthentication(failure: unknown, action: () => Promise<void>): boolean {
    if (errorCode(failure) !== 'REAUTHENTICATION_REQUIRED') return false
    pendingSensitiveAction.current = action
    setReauthOpen(true)
    return true
  }

  async function finishReauthentication(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!reauthPassword.trim() || !client.reauthenticate) return
    const action = pendingSensitiveAction.current
    pendingSensitiveAction.current = null
    try {
      await client.reauthenticate(reauthPassword)
    } catch {
      setError('Reauthentication failed.')
      return
    }
    setReauthOpen(false)
    setReauthPassword('')
    if (!action) return
    try { await action(); setError('') } catch { setError('The operation failed after reauthentication.') }
  }

  function errorCode(failure: unknown): string {
    if (failure instanceof AdminAPIError) return failure.code
    if (failure && typeof failure === 'object' && 'code' in failure && typeof failure.code === 'string') return failure.code
    return ''
  }

  function investigationErrorMessage(failure: unknown, fallback: string): string {
    switch (errorCode(failure)) {
      case 'INVESTIGATION_SCOPE_TOO_BROAD': return 'More than 100 retained audit records matched this scope; narrow the time range.'
      case 'INVESTIGATION_NO_CANDIDATES': return 'No retained audit records matched this employee and time range.'
      default: return fallback
    }
  }

  return <section className="activity-section" aria-labelledby="investigations-title">
    <div className="section-heading-row"><div><p className="section-kicker">Bounded review</p><h2 id="investigations-title">Investigations</h2></div></div>
    {error && <p className="error-state" role="alert">{error}</p>}
    <div className="control-grid investigation-create-form">
      <label className="field-label" htmlFor="investigation-subject">Employee identity ID</label><input id="investigation-subject" value={subject} onChange={(event) => setSubject(event.target.value)} />
      <label className="field-label" htmlFor="investigation-concern">Policy concern</label><input id="investigation-concern" value={concern} onChange={(event) => setConcern(event.target.value)} maxLength={500} />
      <label className="field-label" htmlFor="investigation-reason">Investigation reason</label><input id="investigation-reason" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} />
      <label className="field-label" htmlFor="investigation-start">Start</label><input id="investigation-start" type="datetime-local" value={start} onChange={(event) => setStart(event.target.value)} />
      <label className="field-label" htmlFor="investigation-end">End</label><input id="investigation-end" type="datetime-local" value={end} onChange={(event) => setEnd(event.target.value)} />
      <label className="field-label" htmlFor="investigation-create-confirmed">I confirm this investigation scope</label><input id="investigation-create-confirmed" type="checkbox" checked={createConfirmed} onChange={(event) => setCreateConfirmed(event.target.checked)} />
      <button className="button button-primary" type="button" disabled={!createConfirmed} onClick={() => void createCase()}>Create investigation</button>
    </div>
    <div className="table-wrap" tabIndex={0}><table aria-label="Investigation cases"><thead><tr><th>Subject</th><th>Concern</th><th>Range</th><th>Status</th><th /></tr></thead><tbody>{cases.length ? cases.map((item) => <tr key={item.id}><td>{item.subject_identity_id}</td><td>{item.policy_concern}</td><td>{new Date(item.start_at).toLocaleString()} to {new Date(item.end_at).toLocaleString()}</td><td>{item.status}</td><td><button className="button button-secondary button-small" type="button" onClick={() => void openCase(item)}>Open case</button></td></tr>) : <tr><td colSpan={5} className="empty-row">No investigation cases.</td></tr>}</tbody></table></div>
    {casePagination.next_cursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={casePageLoading} onClick={() => void loadMoreCases()}>{casePageLoading ? 'Loading…' : 'Load more investigation cases'}</button></div>}
    {selected && <div className="investigation-detail"><div className="section-heading-row"><div><p className="section-kicker">Immutable candidate snapshot</p><h3>Case {selected.id}</h3>{grantExpiresAt && selected.status === 'open' && <p>Access expires {new Date(grantExpiresAt).toLocaleString()}</p>}</div>{selected.status === 'open' && client.issueInvestigationGrant && <button className="button button-secondary button-small" type="button" onClick={() => void renewGrant()}>{grantExpiresAt ? 'Renew access' : 'Authorize access'}</button>}</div><div className="table-wrap" tabIndex={0}><table aria-label="Investigation candidates"><thead><tr><th>Audit ID</th><th>Capture</th><th>Expires</th><th /></tr></thead><tbody>{candidates.map((candidate) => <tr key={candidate.audit_id}><td>{candidate.audit_id}</td><td>{candidate.capture_status}</td><td>{new Date(candidate.expires_at).toLocaleString()}</td><td><button className="button button-secondary button-small" type="button" disabled={selected.status !== 'open' || !grantExpiresAt} onClick={() => void inspect(candidate)}>View one record</button></td></tr>)}</tbody></table></div>{view && <div className="investigation-view"><h3>Record {view.audit_id}</h3><p>Request: {view.request.status}</p><pre>{view.request.json ? JSON.stringify(view.request.json, null, 2) : view.request.fragment ?? 'Unavailable'}</pre><p>Response: {view.response.status}</p><pre>{view.response.json ? JSON.stringify(view.response.json, null, 2) : view.response.fragment ?? 'Unavailable'}</pre></div>}{selected.status === 'open' && <div className="control-grid"><label className="field-label" htmlFor="investigation-disposition">Disposition</label><select id="investigation-disposition" value={disposition} onChange={(event) => setDisposition(event.target.value as InvestigationDisposition)}><option value="confirmed_violation">Confirmed violation</option><option value="no_violation">No violation</option><option value="inconclusive">Inconclusive</option></select><label className="field-label" htmlFor="investigation-note">Closure note</label><textarea id="investigation-note" maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} /><label className="field-label" htmlFor="investigation-close-confirmed">I confirm this case closure</label><input id="investigation-close-confirmed" type="checkbox" checked={closeConfirmed} onChange={(event) => setCloseConfirmed(event.target.checked)} /><button className="button button-danger" type="button" disabled={!closeConfirmed} onClick={() => void closeCase()}>Close case</button></div>}</div>}
    {reauthOpen && <ModalDialog ariaLabelledBy="investigation-reauth-title" onDismiss={() => { setReauthOpen(false); setReauthPassword(''); pendingSensitiveAction.current = null }} raised><div className="dialog-heading"><h2 id="investigation-reauth-title">Reauthenticate</h2></div><form className="dialog-form" onSubmit={(event) => void finishReauthentication(event)}><label className="field-label" htmlFor="investigation-reauth-password">Current password</label><input id="investigation-reauth-password" aria-label="Current password" type="password" autoComplete="current-password" value={reauthPassword} onChange={(event) => setReauthPassword(event.target.value)} required /><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => { setReauthOpen(false); setReauthPassword(''); pendingSensitiveAction.current = null }}>Cancel</button><button className="button button-primary" type="submit">Reauthenticate and continue</button></div></form></ModalDialog>}
  </section>
}
