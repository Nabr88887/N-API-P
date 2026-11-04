import { useEffect, useRef, useState } from 'react'

import type { AdminPortalClient, SecurityEventMetadata } from './admin-api'
import { advanceCursor } from './pagination'
import { formatDateTime, t } from './i18n'

export function SecurityEventsWorkspace({ client }: { client: AdminPortalClient }) {
  const [events, setEvents] = useState<SecurityEventMetadata[]>([])
  const [cursor, setCursor] = useState<string | undefined>()
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState('')
  const seenCursors = useRef(new Set<string>())

  useEffect(() => {
    let cancelled = false
    const cursors = new Set<string>()
    seenCursors.current = cursors
    client.listSecurityEvents().then((page) => {
      if (!cancelled) {
        setEvents(page.data)
        setCursor(advanceCursor(page.pagination, cursors))
      }
    }).catch(() => {
      if (!cancelled) setError(t('Unable to load security events.'))
    }).finally(() => {
      if (!cancelled) setLoading(false)
    })
    return () => { cancelled = true }
  }, [client])

  async function loadMore() {
    if (!cursor || loadingMore || !client.listSecurityEvents) return
    setLoadingMore(true)
    setError('')
    try {
      const page = await client.listSecurityEvents({ cursor })
      const nextCursor = advanceCursor(page.pagination, seenCursors.current)
      setEvents((current) => {
        const existing = new Set(current.map((event) => event.id))
        return [...current, ...page.data.filter((event) => !existing.has(event.id))]
      })
      setCursor(nextCursor)
    } catch (failure: unknown) {
      if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setCursor(undefined)
      setError(t('Unable to load more security events.'))
    } finally {
      setLoadingMore(false)
    }
  }

  if (loading) return <section className="activity-section" aria-label={t('Security events')}><p className="loading-state">{t('Loading security events…')}</p></section>
  return <section className="activity-section" aria-labelledby="security-events-title">
    <div className="section-heading-row"><div><p className="section-kicker">{t('Content-free record')}</p><h2 id="security-events-title">{t('Security events')}</h2></div></div>
    {error && <p className="error-state" role="alert">{error}</p>}
    <div className="table-wrap" tabIndex={0}><table aria-label={t('Security events')}><thead><tr><th>{t('When')}</th><th>{t('Event')}</th><th>{t('Actor')}</th><th>{t('Target')}</th><th>{t('Outcome')}</th></tr></thead><tbody>{events.length ? events.map((event) => <tr key={event.id}><td className="muted-cell">{formatDateTime(event.occurred_at)}</td><td>{t(event.event_type)}</td><td>{event.actor_account_id ?? t('System')}</td><td>{event.target_account_id ?? event.target_service_account_id ?? event.target_key_id ?? event.target_audit_id ?? t('Not specified')}</td><td>{t(event.outcome)}</td></tr>) : <tr><td className="empty-row" colSpan={5}>{t('No security events.')}</td></tr>}</tbody></table></div>
    {cursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? t('Loading…') : t('Load more security events')}</button></div>}
  </section>
}
