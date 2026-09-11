import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { AdminAPIError } from './admin-api'
import type { AdminPortalClient, ElevatedAuditGrant, ElevatedAuditQuery, ElevatedAuditRecord } from './admin-api'

export function ElevatedAuditWorkspace({ client }: { client: AdminPortalClient }) {
  const [grant, setGrant] = useState<ElevatedAuditGrant | null>(null)
  const [purpose, setPurpose] = useState('')
  const [query, setQuery] = useState<ElevatedAuditQuery>({ limit: 50 })
  const [records, setRecords] = useState<ElevatedAuditRecord[]>([])
  const [nextCursor, setNextCursor] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [message, setMessage] = useState('')
  const exportController = useRef<AbortController | null>(null)
  const queryGeneration = useRef(0)
  const accessGeneration = useRef(0)
  const submittedQuery = useRef<ElevatedAuditQuery>({ limit: 50 })
  const [reauthOpen, setReauthOpen] = useState(false)
  const [password, setPassword] = useState('')
  const pendingPurpose = useRef('')

  const clearAccess = useCallback((notice: string) => {
    accessGeneration.current++
    queryGeneration.current++
    exportController.current?.abort()
    exportController.current = null
    setGrant(null)
    setRecords([])
    setSelected([])
    setNextCursor('')
    setBusy(false)
    setExporting(false)
    setReauthOpen(false)
    setPassword('')
    setMessage(notice)
  }, [])

  useEffect(() => {
    if (!grant) return
    const remaining = new Date(grant.expires_at).getTime() - Date.now()
    const timer = window.setTimeout(() => clearAccess('Audit grant expired.'), Math.max(remaining, 0))
    return () => window.clearTimeout(timer)
  }, [grant, clearAccess])

  useEffect(() => () => { exportController.current?.abort(); queryGeneration.current++; accessGeneration.current++ }, [])

  function handleFailure(reason: unknown) {
    if (isGrantError(reason)) clearAccess(errorMessage(reason))
    else setMessage(errorMessage(reason))
  }

  async function issueGrant(reason: string, generation: number) {
    if (!client.issueElevatedAuditGrant) return
    const issued = await client.issueElevatedAuditGrant(reason)
    if (generation !== accessGeneration.current) return
    if (!Number.isFinite(Date.parse(issued.expires_at)) || Date.parse(issued.expires_at) <= Date.now()) {
      clearAccess('Audit grant expired.')
      return
    }
    setGrant(issued)
    setReauthOpen(false)
    setPassword('')
  }

  async function activate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!purpose.trim() || busy || !client.issueElevatedAuditGrant) return
    const generation = ++accessGeneration.current
    pendingPurpose.current = purpose.trim()
    setBusy(true); setMessage('')
    try {
      await issueGrant(pendingPurpose.current, generation)
    } catch (reason) {
      if (generation !== accessGeneration.current) return
      if (reason instanceof AdminAPIError && reason.code === 'REAUTHENTICATION_REQUIRED') setReauthOpen(true)
      else handleFailure(reason)
    } finally { if (generation === accessGeneration.current) setBusy(false) }
  }

  async function finishReauthentication(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!password || busy) return
    const generation = accessGeneration.current
    const submittedPassword = password
    setPassword(''); setBusy(true); setMessage('')
    try {
      await client.reauthenticate(submittedPassword)
      if (generation === accessGeneration.current) await issueGrant(pendingPurpose.current, generation)
    } catch (reason) { if (generation === accessGeneration.current) handleFailure(reason) }
    finally { if (generation === accessGeneration.current) setBusy(false) }
  }

  async function search() {
    if (!grant || busy || !client.queryElevatedAudits) return
    const generation = ++queryGeneration.current
    submittedQuery.current = { ...query, cursor: undefined }
    setBusy(true); setMessage(''); setRecords([]); setSelected([]); setNextCursor('')
    try { const page = await client.queryElevatedAudits(submittedQuery.current); if (generation === queryGeneration.current && Date.parse(grant.expires_at) > Date.now()) { setRecords(page.data); setNextCursor(page.pagination.next_cursor ?? ''); setSelected([]) } } catch (reason) { if (generation === queryGeneration.current) handleFailure(reason) } finally { if (generation === queryGeneration.current) setBusy(false) }
  }

  async function loadMore() {
    if (!grant || !nextCursor || busy || !client.queryElevatedAudits) return
    const generation = ++queryGeneration.current
    setBusy(true); setMessage(''); setRecords([]); setSelected([])
    try { const page = await client.queryElevatedAudits({ ...submittedQuery.current, cursor: nextCursor }); if (generation === queryGeneration.current && Date.parse(grant.expires_at) > Date.now()) { setRecords(page.data); setNextCursor(page.pagination.next_cursor === nextCursor ? '' : page.pagination.next_cursor ?? '') } } catch (reason) { if (generation === queryGeneration.current) handleFailure(reason) } finally { if (generation === queryGeneration.current) setBusy(false) }
  }

  async function batchView() {
    if (!grant || !selected.length || busy || !client.batchViewElevatedAudits) return
    const generation = ++queryGeneration.current
    const auditIDs = [...selected]
    submittedQuery.current = { audit_ids: auditIDs, limit: 1000 }
    setBusy(true); setMessage(''); setRecords([]); setSelected([]); setNextCursor('')
    try { const page = await client.batchViewElevatedAudits(auditIDs); if (generation === queryGeneration.current && Date.parse(grant.expires_at) > Date.now()) { setRecords(page.data); setNextCursor(page.pagination.next_cursor ?? '') } } catch (reason) { if (generation === queryGeneration.current) handleFailure(reason) } finally { if (generation === queryGeneration.current) setBusy(false) }
  }

  async function exportJSONL() {
    if (!grant || exporting || !client.exportElevatedAudits) return
    const controller = new AbortController()
    const generation = accessGeneration.current
    exportController.current = controller
    setExporting(true); setMessage('')
    try {
      const blob = await client.exportElevatedAudits(query, controller.signal)
      if (generation !== accessGeneration.current || controller.signal.aborted || Date.parse(grant.expires_at) <= Date.now()) return
      const url = URL.createObjectURL(blob)
      try {
        const link = document.createElement('a')
        link.href = url; link.download = 'audit-export.jsonl'; link.click()
      } finally { URL.revokeObjectURL(url) }
      setMessage('Export complete.')
    } catch (reason) {
      if (generation !== accessGeneration.current) return
      if (controller.signal.aborted || (reason instanceof Error && reason.name === 'AbortError')) setMessage('Export cancelled.')
      else handleFailure(reason)
    } finally { if (exportController.current === controller) { exportController.current = null; setExporting(false) } }
  }

  async function revoke() {
    if (!grant || busy || !client.revokeElevatedAuditGrant) return
    const generation = accessGeneration.current
    exportController.current?.abort()
    setBusy(true); setMessage('')
    try { await client.revokeElevatedAuditGrant(); if (generation === accessGeneration.current) clearAccess('Audit access revoked') } catch (reason) { if (generation === accessGeneration.current) handleFailure(reason) } finally { if (generation === accessGeneration.current) setBusy(false) }
  }

  return <section className="activity-section" aria-labelledby="elevated-audit-title">
    <div className="section-heading-row"><div><p className="section-kicker">Privileged audit mode</p><h2 id="elevated-audit-title">Elevated audit access</h2></div>{grant && <span className="status-chip">Grant active · expires {new Date(grant.expires_at).toLocaleString()}</span>}</div>
    {message && <p className="error-state" role="status">{message}</p>}
    {reauthOpen && <form className="dialog-form" onSubmit={finishReauthentication}><label className="field-label" htmlFor="elevated-audit-password">Current password</label><input id="elevated-audit-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><div className="dialog-actions"><button type="submit" className="button button-primary" disabled={busy}>Complete security check</button><button type="button" className="button button-secondary" onClick={() => clearAccess('Security check cancelled.')}>Cancel security check</button></div></form>}
    {!grant ? <form className="dialog-form" onSubmit={activate}><label className="field-label" htmlFor="grant-purpose">Grant purpose</label><textarea id="grant-purpose" aria-label="Grant purpose" maxLength={500} value={purpose} onChange={(event) => setPurpose(event.target.value)} required /><div className="dialog-actions"><button className="button button-primary" type="submit" disabled={busy || !purpose.trim()}>{busy ? 'Activating…' : 'Activate 24-hour audit access'}</button></div></form> : <>
      <form className="query-grid" onSubmit={(event) => { event.preventDefault(); void search() }}><label className="field-label" htmlFor="audit-identity">Employee ID<input id="audit-identity" value={query.identity_id ?? ''} onChange={(event) => setQuery({ ...query, identity_id: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-service">Service account ID<input id="audit-service" value={query.service_account_id ?? ''} onChange={(event) => setQuery({ ...query, service_account_id: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-responsible">Responsible employee ID<input id="audit-responsible" value={query.responsible_identity_id ?? ''} onChange={(event) => setQuery({ ...query, responsible_identity_id: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-owner">Owner kind<select id="audit-owner" value={query.owner_kind ?? ''} onChange={(event) => setQuery({ ...query, owner_kind: (event.target.value || undefined) as ElevatedAuditQuery['owner_kind'] })}><option value="">All owners</option><option value="personal">Personal</option><option value="service">Service account</option></select></label><label className="field-label" htmlFor="audit-model">Model ID<input id="audit-model" value={query.model_id ?? ''} onChange={(event) => setQuery({ ...query, model_id: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-status">Capture status<select id="audit-status" value={query.capture_status ?? ''} onChange={(event) => setQuery({ ...query, capture_status: (event.target.value || undefined) as ElevatedAuditQuery['capture_status'] })}><option value="">All capture states</option><option value="complete">Complete</option><option value="truncated">Truncated</option><option value="incomplete">Incomplete</option><option value="pending">Pending</option></select></label><label className="field-label" htmlFor="audit-outcome">Outcome<select id="audit-outcome" value={query.outcome ?? ''} onChange={(event) => setQuery({ ...query, outcome: (event.target.value || undefined) as ElevatedAuditQuery['outcome'] })}><option value="">All outcomes</option><option value="success">Success</option><option value="upstream_error">Upstream error</option><option value="cancelled">Cancelled</option><option value="local_error">Local error</option></select></label><label className="field-label" htmlFor="audit-from">From<input id="audit-from" type="datetime-local" value={query.from ?? ''} onChange={(event) => setQuery({ ...query, from: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-to">To<input id="audit-to" type="datetime-local" value={query.to ?? ''} onChange={(event) => setQuery({ ...query, to: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-text">Full-text filter<input id="audit-text" value={query.full_text ?? ''} onChange={(event) => setQuery({ ...query, full_text: event.target.value || undefined })} /></label><div className="dialog-actions"><button className="button button-primary" type="submit" disabled={busy}>Search retained audits</button><button className="button button-secondary" type="button" disabled={busy} onClick={() => void exportJSONL()}>{exporting ? 'Exporting…' : 'Export JSONL'}</button><button className="button button-danger" type="button" disabled={busy} onClick={() => void revoke()}>Revoke audit access</button>{exporting && <button className="button button-secondary" type="button" onClick={() => exportController.current?.abort()}>Cancel export</button>}</div></form>
      <div className="table-wrap" tabIndex={0}><table aria-label="Elevated audit results"><thead><tr><th>Select</th><th>Audit ID</th><th>Created</th><th>Owner</th><th>Model</th><th>Capture</th><th>Outcome</th><th>Usage</th></tr></thead><tbody>{records.length ? records.map((record) => <tr key={record.id}><td><input type="checkbox" aria-label={`Select audit ${record.id}`} checked={selected.includes(record.id)} onChange={() => setSelected((current) => current.includes(record.id) ? current.filter((id) => id !== record.id) : [...current, record.id])} /></td><td>{record.id}</td><td>{new Date(record.created_at).toLocaleString()}</td><td>{record.identity_id ?? record.service_account_id ?? 'Unknown'}</td><td>{record.model_id}</td><td>{record.request_capture_status} / {record.response_capture_status}</td><td>{record.outcome}</td><td>{record.usage ? `${record.usage.input_tokens} / ${record.usage.output_tokens} / ${record.usage.total_tokens}` : 'Unavailable'}</td></tr>) : <tr><td colSpan={8} className="empty-row">No retained audits loaded.</td></tr>}</tbody></table></div><div className="dialog-actions"><button className="button button-secondary" type="button" disabled={!selected.length || busy} onClick={() => void batchView()}>View selected audits</button></div>
      {nextCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={busy} onClick={() => void loadMore()}>{busy ? 'Loading…' : 'Load more retained audits'}</button></div>}
      {records.map((record) => <details key={record.id} className="raw-audit-content"><summary>Raw content for {record.id}</summary><section><h3>Request · {record.request_capture_status}</h3><pre>{record.request_fragment ?? JSON.stringify(record.request ?? null, null, 2)}</pre></section><section><h3>Response · {record.response_capture_status}</h3><pre>{record.response_fragment ?? JSON.stringify(record.response ?? null, null, 2)}</pre></section></details>)}
    </>}
  </section>
}

function isGrantError(reason: unknown): boolean { const code = reason instanceof AdminAPIError ? reason.code : ''; return ['GRANT_EXPIRED', 'GRANT_REVOKED', 'FORBIDDEN', 'AUTHENTICATION_REQUIRED'].includes(code) }
function errorMessage(reason: unknown): string { if (isGrantError(reason)) return 'Audit grant expired or was revoked.'; if (reason instanceof AdminAPIError && reason.code === 'EXPORT_INCOMPLETE') return 'Export incomplete.'; return 'Unable to complete elevated audit operation.' }
