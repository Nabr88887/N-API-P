import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { AdminAPIError } from './admin-api'
import type { AdminPortalClient, ElevatedAuditGrant, ElevatedAuditQuery, ElevatedAuditRecord } from './admin-api'
import { formatDateTime, t } from './i18n'

type ElevatedAuditExportWritable = {
  write(data: Uint8Array): Promise<void>
  close(): Promise<void>
  abort?(reason?: unknown): Promise<void>
}

type ElevatedAuditExportFileHandle = { createWritable(): Promise<ElevatedAuditExportWritable> }

type ElevatedAuditExportFilePicker = (options: {
  suggestedName: string
  types: Array<{ description: string; accept: Record<string, string[]> }>
}) => Promise<ElevatedAuditExportFileHandle>

type ExportWindow = Window & { showSaveFilePicker?: ElevatedAuditExportFilePicker }

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
    const timer = window.setTimeout(() => clearAccess(t('Audit grant expired.')), Math.max(remaining, 0))
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
      clearAccess(t('Audit grant expired.'))
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
    let writable: ElevatedAuditExportWritable | null = null
    setExporting(true); setMessage('')
    try {
      writable = await openElevatedAuditExportWriter()
      const stream = await client.exportElevatedAudits(query, controller.signal)
      await writeElevatedAuditExport(stream, writable, controller.signal)
      writable = null
      if (generation !== accessGeneration.current || controller.signal.aborted || Date.parse(grant.expires_at) <= Date.now()) return
      setMessage(t('Export complete.'))
    } catch (reason) {
      if (writable) await abortElevatedAuditExportWriter(writable, reason)
      if (generation !== accessGeneration.current) return
      if (controller.signal.aborted || (reason instanceof Error && reason.name === 'AbortError')) setMessage(t('Export cancelled.'))
      else handleFailure(reason)
    } finally { if (exportController.current === controller) { exportController.current = null; setExporting(false) } }
  }

  async function revoke() {
    if (!grant || busy || !client.revokeElevatedAuditGrant) return
    const generation = accessGeneration.current
    exportController.current?.abort()
    setBusy(true); setMessage('')
    try { await client.revokeElevatedAuditGrant(); if (generation === accessGeneration.current) clearAccess(t('Audit access revoked')) } catch (reason) { if (generation === accessGeneration.current) handleFailure(reason) } finally { if (generation === accessGeneration.current) setBusy(false) }
  }

  return <section className="activity-section" aria-labelledby="elevated-audit-title">
    <div className="section-heading-row"><div><p className="section-kicker">{t('Privileged audit mode')}</p><h2 id="elevated-audit-title">{t('Elevated audit access')}</h2></div>{grant && <span className="status-chip">{t('Grant active · expires {date}', { date: formatDateTime(grant.expires_at) })}</span>}</div>
    {message && <p className="error-state" role="status">{message}</p>}
    {reauthOpen && <form className="dialog-form" onSubmit={finishReauthentication}><label className="field-label" htmlFor="elevated-audit-password">{t('Current password')}</label><input id="elevated-audit-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><div className="dialog-actions"><button type="submit" className="button button-primary" disabled={busy}>{t('Complete security check')}</button><button type="button" className="button button-secondary" onClick={() => clearAccess(t('Security check cancelled.'))}>{t('Cancel security check')}</button></div></form>}
    {!grant ? <form className="dialog-form" onSubmit={activate}><label className="field-label" htmlFor="grant-purpose">{t('Grant purpose')}</label><textarea id="grant-purpose" aria-label={t('Grant purpose')} maxLength={500} value={purpose} onChange={(event) => setPurpose(event.target.value)} required /><div className="dialog-actions"><button className="button button-primary" type="submit" disabled={busy || !purpose.trim()}>{busy ? t('Activating…') : t('Activate 24-hour audit access')}</button></div></form> : <>
      <form className="query-grid" onSubmit={(event) => { event.preventDefault(); void search() }}><label className="field-label" htmlFor="audit-identity">{t('Employee ID')}<input id="audit-identity" value={query.identity_id ?? ''} onChange={(event) => setQuery({ ...query, identity_id: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-service">{t('Service account ID')}<input id="audit-service" value={query.service_account_id ?? ''} onChange={(event) => setQuery({ ...query, service_account_id: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-responsible">{t('Responsible employee ID')}<input id="audit-responsible" value={query.responsible_identity_id ?? ''} onChange={(event) => setQuery({ ...query, responsible_identity_id: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-owner">{t('Owner kind')}<select id="audit-owner" value={query.owner_kind ?? ''} onChange={(event) => setQuery({ ...query, owner_kind: (event.target.value || undefined) as ElevatedAuditQuery['owner_kind'] })}><option value="">{t('All owners')}</option><option value="personal">{t('Personal')}</option><option value="service">{t('Service account')}</option></select></label><label className="field-label" htmlFor="audit-model">{t('Model ID')}<input id="audit-model" value={query.model_id ?? ''} onChange={(event) => setQuery({ ...query, model_id: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-status">{t('Capture status')}<select id="audit-status" value={query.capture_status ?? ''} onChange={(event) => setQuery({ ...query, capture_status: (event.target.value || undefined) as ElevatedAuditQuery['capture_status'] })}><option value="">{t('All capture states')}</option><option value="complete">{t('Complete')}</option><option value="truncated">{t('Truncated')}</option><option value="incomplete">{t('Incomplete')}</option><option value="pending">{t('Pending')}</option></select></label><label className="field-label" htmlFor="audit-outcome">{t('Outcome')}<select id="audit-outcome" value={query.outcome ?? ''} onChange={(event) => setQuery({ ...query, outcome: (event.target.value || undefined) as ElevatedAuditQuery['outcome'] })}><option value="">{t('All outcomes')}</option><option value="success">{t('Success')}</option><option value="upstream_error">{t('Upstream error')}</option><option value="cancelled">{t('Cancelled')}</option><option value="local_error">{t('Local error')}</option></select></label><label className="field-label" htmlFor="audit-from">{t('From')}<input id="audit-from" type="datetime-local" value={query.from ?? ''} onChange={(event) => setQuery({ ...query, from: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-to">{t('To')}<input id="audit-to" type="datetime-local" value={query.to ?? ''} onChange={(event) => setQuery({ ...query, to: event.target.value || undefined })} /></label><label className="field-label" htmlFor="audit-text">{t('Full-text filter')}<input id="audit-text" value={query.full_text ?? ''} onChange={(event) => setQuery({ ...query, full_text: event.target.value || undefined })} /></label><div className="dialog-actions"><button className="button button-primary" type="submit" disabled={busy}>{t('Search retained audits')}</button><button className="button button-secondary" type="button" disabled={busy} onClick={() => void exportJSONL()}>{exporting ? t('Exporting…') : t('Export JSONL')}</button><button className="button button-danger" type="button" disabled={busy} onClick={() => void revoke()}>{t('Revoke audit access')}</button>{exporting && <button className="button button-secondary" type="button" onClick={() => exportController.current?.abort()}>{t('Cancel export')}</button>}</div></form>
      <div className="table-wrap" tabIndex={0}><table aria-label={t('Elevated audit results')}><thead><tr><th>{t('Select')}</th><th>{t('Audit ID')}</th><th>{t('Created')}</th><th>{t('Owner')}</th><th>{t('Model')}</th><th>{t('Capture')}</th><th>{t('Outcome')}</th><th>{t('Usage')}</th></tr></thead><tbody>{records.length ? records.map((record) => <tr key={record.id}><td><input type="checkbox" aria-label={t('Select audit {id}', { id: record.id })} checked={selected.includes(record.id)} onChange={() => setSelected((current) => current.includes(record.id) ? current.filter((id) => id !== record.id) : [...current, record.id])} /></td><td>{record.id}</td><td>{formatDateTime(record.created_at)}</td><td>{record.identity_id ?? record.service_account_id ?? t('Unknown')}</td><td>{record.model_id}</td><td>{t(record.request_capture_status)} / {t(record.response_capture_status)}</td><td>{t(record.outcome)}</td><td>{record.usage ? `${record.usage.input_tokens} / ${record.usage.output_tokens} / ${record.usage.total_tokens}` : t('Unavailable')}</td></tr>) : <tr><td colSpan={8} className="empty-row">{t('No retained audits loaded.')}</td></tr>}</tbody></table></div><div className="dialog-actions"><button className="button button-secondary" type="button" disabled={!selected.length || busy} onClick={() => void batchView()}>{t('View selected audits')}</button></div>
      {nextCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={busy} onClick={() => void loadMore()}>{busy ? t('Loading…') : t('Load more retained audits')}</button></div>}
      {records.map((record) => <details key={record.id} className="raw-audit-content"><summary>{t('Raw content for {id}', { id: record.id })}</summary><section><h3>{t('Request')} · {t(record.request_capture_status)}</h3><pre>{record.request_fragment ?? JSON.stringify(record.request ?? null, null, 2)}</pre></section><section><h3>{t('Response')} · {t(record.response_capture_status)}</h3><pre>{record.response_fragment ?? JSON.stringify(record.response ?? null, null, 2)}</pre></section></details>)}
    </>}
  </section>
}

function isGrantError(reason: unknown): boolean { const code = reason instanceof AdminAPIError ? reason.code : ''; return ['GRANT_EXPIRED', 'GRANT_REVOKED', 'FORBIDDEN', 'AUTHENTICATION_REQUIRED'].includes(code) }
function errorMessage(reason: unknown): string { if (isGrantError(reason)) return t('Audit grant expired or was revoked.'); if (reason instanceof AdminAPIError && reason.code === 'EXPORT_INCOMPLETE') return t('Export incomplete.'); if (reason instanceof AdminAPIError && reason.code === 'EXPORT_STREAMING_UNSUPPORTED') return t('This browser cannot stream exports directly to a file.'); return t('Unable to complete elevated audit operation.') }

async function openElevatedAuditExportWriter(): Promise<ElevatedAuditExportWritable> {
  const picker = (window as ExportWindow).showSaveFilePicker
  if (!picker) throw new AdminAPIError('EXPORT_STREAMING_UNSUPPORTED')
  const handle = await picker({ suggestedName: 'audit-export.jsonl', types: [{ description: 'JSONL audit export', accept: { 'application/x-ndjson': ['.jsonl'] } }] })
  return handle.createWritable()
}

async function writeElevatedAuditExport(stream: ReadableStream<Uint8Array>, writable: ElevatedAuditExportWritable, signal: AbortSignal): Promise<void> {
  const reader = stream.getReader()
  try {
    for (;;) {
      if (signal.aborted) throw signal.reason ?? new DOMException('The export was cancelled.', 'AbortError')
      const { done, value } = await reader.read()
      if (done) {
        await writable.close()
        return
      }
      if (!value) throw new AdminAPIError('EXPORT_INCOMPLETE')
      await writable.write(value)
    }
  } catch (reason) {
    await reader.cancel(reason).catch(() => {})
    await abortElevatedAuditExportWriter(writable, reason)
    throw reason
  } finally {
    reader.releaseLock()
  }
}

async function abortElevatedAuditExportWriter(writable: ElevatedAuditExportWritable, reason: unknown): Promise<void> {
  try {
    await writable.abort?.(reason)
  } catch {
    return
  }
}
