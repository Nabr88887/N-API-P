import { useEffect, useState, type FormEvent } from 'react'

import { AdminAPIError } from './admin-api'
import type { AdminPortalClient, AuditMetadata, Pagination, RawAuditView } from './admin-api'
import { ModalDialog } from './ModalDialog'

type Props = { client: AdminPortalClient }

export function AuditWorkspace({ client }: Props) {
  const [records, setRecords] = useState<AuditMetadata[]>([])
  const [pagination, setPagination] = useState<Pagination>({ has_more: false })
  const [loading, setLoading] = useState(true)
  const [pageLoading, setPageLoading] = useState(false)
  const [error, setError] = useState('')
  const [target, setTarget] = useState<AuditMetadata | null>(null)
  const [reason, setReason] = useState('')
  const [rawView, setRawView] = useState<RawAuditView | null>(null)
  const [reauthOpen, setReauthOpen] = useState(false)
  const [password, setPassword] = useState('')

  useEffect(() => {
    let cancelled = false
    client.listAudits().then((page) => {
      if (!cancelled) {
        setRecords(page.data)
        setPagination(page.pagination)
      }
    }).catch(() => {
      if (!cancelled) setError('Unable to load audit metadata.')
    }).finally(() => {
      if (!cancelled) setLoading(false)
    })
    return () => { cancelled = true }
  }, [client])

  async function loadMore() {
    if (!pagination.next_cursor || pageLoading) return
    setPageLoading(true)
    setError('')
    try {
      const page = await client.listAudits({ cursor: pagination.next_cursor })
      setRecords((current) => appendUnique(current, page.data))
      setPagination(page.pagination)
    } catch {
      setError('Unable to load more audit metadata.')
    } finally {
      setPageLoading(false)
    }
  }

  function beginInspection(record: AuditMetadata) {
    setTarget(record)
    setReason('')
    setRawView(null)
    setError('')
  }

  async function inspect() {
    if (!target || !reason.trim()) return
    try {
      const view = await client.inspectAudit(target.id, reason.trim())
      setRawView(view)
      setTarget(null)
    } catch (failure: unknown) {
      if (errorCode(failure) === 'REAUTHENTICATION_REQUIRED') {
        setReauthOpen(true)
      } else {
        setError('Unable to inspect this audit record.')
      }
    }
  }

  async function finishReauthentication(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      await client.reauthenticate(password)
      setPassword('')
      setReauthOpen(false)
      await inspect()
    } catch {
      setError('Reauthentication failed.')
    }
  }

  function closeRawView() {
    setRawView(null)
    setReason('')
  }

  if (loading) return <section className="activity-section" aria-label="Audit"><p className="loading-state">Loading audit metadata…</p></section>

  return <>
    <section className="activity-section" aria-labelledby="audit-metadata-title">
      <div className="section-heading-row"><div><p className="section-kicker">Content-free records</p><h2 id="audit-metadata-title">Audit metadata</h2></div></div>
      {error && <p className="error-state" role="alert">{error}</p>}
      <div className="table-wrap" tabIndex={0}><table aria-label="Audit metadata"><thead><tr><th>Created</th><th>Model</th><th>Capture</th><th>Outcome</th><th>Bytes</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
        {records.length ? records.map((record) => <tr key={record.id}><td className="muted-cell">{new Date(record.created_at).toLocaleString()}</td><td className="audit-model-cell">{record.model_id}</td><td>{record.capture_status}</td><td>{record.outcome}</td><td className="muted-cell">{record.observed_request_bytes} / {record.observed_response_bytes}</td><td><button className="button button-secondary button-small" type="button" onClick={() => beginInspection(record)} aria-label={`Inspect raw content for ${record.id}`}>Inspect</button></td></tr>) : <tr><td colSpan={6} className="empty-row">No audit records yet.</td></tr>}
      </tbody></table></div>
      {pagination.has_more && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={pageLoading} onClick={() => void loadMore()}>{pageLoading ? 'Loading…' : 'Load more audits'}</button></div>}
    </section>

    {target && <ModalDialog ariaLabelledBy="inspection-title" onDismiss={() => setTarget(null)}><div className="dialog-heading"><h2 id="inspection-title">Inspect one audit record</h2></div><form className="dialog-form" onSubmit={(event) => { event.preventDefault(); void inspect() }}><label className="field-label" htmlFor="inspection-reason">Investigation reason</label><textarea id="inspection-reason" name="investigation_reason" aria-label="Investigation reason" autoComplete="off" spellCheck={true} maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} required /><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setTarget(null)}>Cancel</button><button className="button button-primary" type="submit" disabled={!reason.trim()}>Inspect one record</button></div></form></ModalDialog>}

    {reauthOpen && <ModalDialog ariaLabelledBy="audit-reauth-title" onDismiss={() => setReauthOpen(false)} raised><div className="dialog-heading"><h2 id="audit-reauth-title">Reauthenticate</h2></div><form className="dialog-form" onSubmit={finishReauthentication}><label className="field-label" htmlFor="audit-reauth-password">Current password</label><input id="audit-reauth-password" name="current_password" aria-label="Current password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setReauthOpen(false)}>Cancel</button><button className="button button-primary" type="submit">Reauthenticate and continue</button></div></form></ModalDialog>}

    {rawView && <ModalDialog ariaLabelledBy="raw-audit-title" className="dialog-wide raw-audit-dialog" onDismiss={closeRawView}><div className="dialog-heading"><div><p className="section-kicker">Single record</p><h2 id="raw-audit-title">Raw audit record</h2></div></div><div className="raw-audit-content"><section aria-labelledby="raw-request-title"><h3 id="raw-request-title">Request</h3><pre tabIndex={0}>{formatJSON(rawView.request)}</pre></section><section aria-labelledby="raw-response-title"><h3 id="raw-response-title">Response</h3><pre tabIndex={0}>{formatJSON(rawView.response)}</pre></section></div><div className="dialog-actions"><button className="button button-primary" type="button" onClick={closeRawView}>Close raw audit record</button></div></ModalDialog>}
  </>
}

function appendUnique(current: AuditMetadata[], next: AuditMetadata[]): AuditMetadata[] {
  const existing = new Set(current.map((record) => record.id))
  return [...current, ...next.filter((record) => !existing.has(record.id))]
}

function formatJSON(value: unknown): string {
  return JSON.stringify(value, null, 2) ?? 'null'
}

function errorCode(reason: unknown): string {
  if (reason instanceof AdminAPIError) return reason.code
  if (reason && typeof reason === 'object' && 'code' in reason && typeof reason.code === 'string') return reason.code
  return ''
}
