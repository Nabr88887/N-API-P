import type { HealthResponse } from './admin-api'

export const faultCopy = {
  audit_unavailable: 'Audit persistence unavailable',
  raw_deletion_overdue: 'Raw content deletion overdue',
  required_key_failure: 'Required audit key unavailable',
  database_unavailable: 'Database unavailable',
} as const

export type FaultCode = keyof typeof faultCopy

export function activeCriticalFaults(health: HealthResponse | null): FaultCode[] {
  if (!health) return []
  return health.components.flatMap((component) => (
    component.state !== 'healthy' && isFaultCode(component.name) ? [component.name] : []
  ))
}

export function isFaultCode(value: string): value is FaultCode {
  return Object.prototype.hasOwnProperty.call(faultCopy, value)
}
