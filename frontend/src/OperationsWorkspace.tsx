import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2 } from 'lucide-react'

import type { AdminPortalClient, HealthResponse, OperationalEvent } from './admin-api'
import { activeCriticalFaults, faultCopy, isFaultCode, type FaultCode } from './operational-faults'
type SafeOperationalEvent = OperationalEvent & { event_type: FaultCode; severity: 'critical' | 'recovery' }

export function CriticalFaultBanners({ health }: { health: HealthResponse | null }) {
  const faults = activeCriticalFaults(health)
  if (!faults.length) return null
  return (
    <div className="critical-fault-stack" aria-label="Critical operational faults">
      {faults.map((fault) => (
        <section className="critical-fault-banner" role="alert" aria-label={faultCopy[fault]} key={fault}>
          <AlertTriangle size={20} aria-hidden="true" />
          <div><span>Critical operational fault</span><strong>{faultCopy[fault]}</strong></div>
        </section>
      ))}
    </div>
  )
}

export function OperationsWorkspace({ client }: { client: AdminPortalClient }) {
  const [events, setEvents] = useState<SafeOperationalEvent[]>([])
  const [cursor, setCursor] = useState<string | undefined>()
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    client.listOperationalEvents().then((page) => {
      if (!cancelled) {
        setEvents(safeEvents(page.data))
        setCursor(page.pagination.next_cursor)
      }
    }).catch(() => {
      if (!cancelled) setError('Unable to load operational events.')
    }).finally(() => {
      if (!cancelled) setLoading(false)
    })
    return () => { cancelled = true }
  }, [client])

  async function loadMore() {
    if (!cursor || loadingMore) return
    setLoadingMore(true)
    setError('')
    try {
      const page = await client.listOperationalEvents({ cursor })
      setEvents((current) => appendEvents(current, safeEvents(page.data)))
      setCursor(page.pagination.next_cursor)
    } catch {
      setError('Unable to load more operational events.')
    } finally {
      setLoadingMore(false)
    }
  }

  if (loading) return <section className="activity-section" aria-label="Operations"><p className="loading-state">Loading operations…</p></section>
  return (
    <section className="activity-section" aria-labelledby="operations-events-title">
      <div className="section-heading-row">
        <div><p className="section-kicker">Content-free record</p><h2 id="operations-events-title">Recent operational events</h2></div>
      </div>
      {error && <p className="error-state" role="alert">{error}</p>}
      <div className="table-wrap" tabIndex={0}>
        <table aria-label="Recent operational events">
          <thead><tr><th scope="col">When</th><th scope="col">Condition</th><th scope="col">Status</th></tr></thead>
          <tbody>
            {events.length ? events.map((event) => (
              <tr key={event.id}>
                <td className="muted-cell">{new Date(event.occurred_at).toLocaleString()}</td>
                <td>{faultCopy[event.event_type]}</td>
                <td><span className={`operation-state operation-state-${event.severity}`}>
                  {event.severity === 'critical' ? <AlertTriangle size={14} aria-hidden="true" /> : <CheckCircle2 size={14} aria-hidden="true" />}
                  {event.severity === 'critical' ? 'Critical' : 'Recovered'}
                </span></td>
              </tr>
            )) : <tr><td className="empty-row" colSpan={3}>No recent operational events.</td></tr>}
          </tbody>
        </table>
      </div>
      {cursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? 'Loading…' : 'Load more events'}</button></div>}
    </section>
  )
}

function safeEvents(events: OperationalEvent[]): SafeOperationalEvent[] {
  return events.flatMap((event) => (
    isFaultCode(event.event_type) && (event.severity === 'critical' || event.severity === 'recovery')
      ? [event as SafeOperationalEvent]
      : []
  ))
}

function appendEvents(current: SafeOperationalEvent[], next: SafeOperationalEvent[]): SafeOperationalEvent[] {
  const existing = new Set(current.map((event) => event.id))
  return [...current, ...next.filter((event) => !existing.has(event.id))]
}
