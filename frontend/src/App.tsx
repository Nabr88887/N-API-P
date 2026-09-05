import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import {
  Activity,
  Bell,
  Boxes,
  ChevronRight,
  CircleHelp,
  FileClock,
  KeyRound,
  LayoutDashboard,
  Menu,
  PanelLeftClose,
  ServerCog,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  UsersRound,
  X,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import { createEmployeePortalClient, type EmployeePortalClient, type KeyIssuance, type PersonalKey, type UsageRecord } from './employee-api'
import { TeamWorkspace } from './TeamWorkspace'
import { createTeamPortalClient, type TeamPortalClient } from './team-api'
import { createAdminPortalClient, type AdminPortalClient, type HealthResponse } from './admin-api'
import { SystemAdminWorkspace } from './SystemAdminWorkspace'
import { CriticalFaultBanners } from './OperationsWorkspace'
import { SecurityEventsWorkspace } from './SecurityEventsWorkspace'
import { InvestigationWorkspace } from './InvestigationWorkspace'
import { activeCriticalFaults } from './operational-faults'
import { ModalDialog } from './ModalDialog'
import { trapTabKey } from './focus-management'
import { advanceCursor } from './pagination'

import './app.css'

export type Role = 'employee' | 'team_administrator' | 'system_administrator'

type NavItem = {
  label: string
  icon: LucideIcon
}

type RoleProfile = {
  label: string
  eyebrow: string
  description: string
  nav: NavItem[]
}

const roleProfiles: Record<Role, RoleProfile> = {
  employee: {
    label: 'Employee',
    eyebrow: 'Personal workspace',
    description: 'Your access and usage, kept in one place.',
    nav: [
      { label: 'Overview', icon: LayoutDashboard },
      { label: 'My keys', icon: KeyRound },
      { label: 'My usage', icon: Activity },
    ],
  },
  team_administrator: {
    label: 'Team administrator',
    eyebrow: 'Team workspace',
    description: 'Membership and usage metadata for your team.',
    nav: [
      { label: 'Overview', icon: LayoutDashboard },
      { label: 'Team members', icon: UsersRound },
      { label: 'Team usage', icon: Activity },
    ],
  },
  system_administrator: {
    label: 'System administrator',
    eyebrow: 'Governance workspace',
    description: 'A controlled view of access, policy, and operations.',
    nav: [
      { label: 'Overview', icon: LayoutDashboard },
      { label: 'People & teams', icon: UsersRound },
      { label: 'Service accounts', icon: ServerCog },
      { label: 'Model policy', icon: Boxes },
      { label: 'Retention', icon: FileClock },
      { label: 'Audit', icon: FileClock },
      { label: 'Investigations', icon: ShieldAlert },
      { label: 'Security events', icon: ShieldAlert },
      { label: 'Operations', icon: Settings2 },
    ],
  },
}

function roleName(role: Role): string {
  return roleProfiles[role].label
}

export function App({ role = 'system_administrator', employeeClient: injectedEmployeeClient, teamClient: injectedTeamClient, adminClient: injectedAdminClient, teamID = '', teamIDs, identityEmail = '', onLogout }: { role?: Role; employeeClient?: EmployeePortalClient; teamClient?: TeamPortalClient; adminClient?: AdminPortalClient; teamID?: string; teamIDs?: string[]; identityEmail?: string; onLogout?: () => Promise<void> }) {
  const profile = roleProfiles[role]
  const [activeSection, setActiveSection] = useState('Overview')
  const [navigationOpen, setNavigationOpen] = useState(false)
  const [sessionDialogOpen, setSessionDialogOpen] = useState(false)
  const [employeeClient] = useState(() => injectedEmployeeClient ?? createEmployeePortalClient())
  const [teamClient] = useState(() => injectedTeamClient ?? createTeamPortalClient())
  const [adminClient] = useState(() => injectedAdminClient ?? createAdminPortalClient())
  const [operationsHealth, setOperationsHealth] = useState<HealthResponse | null>(null)
  const [personalKeys, setPersonalKeys] = useState<PersonalKey[]>([])
  const [usageRecords, setUsageRecords] = useState<UsageRecord[]>([])
  const [personalKeyCursor, setPersonalKeyCursor] = useState<string | undefined>()
  const [usageCursor, setUsageCursor] = useState<string | undefined>()
  const [employeeLoading, setEmployeeLoading] = useState(false)
  const [employeeError, setEmployeeError] = useState('')
  const [employeeSubmitting, setEmployeeSubmitting] = useState(false)
  const [employeePageLoading, setEmployeePageLoading] = useState(false)
  const [employeePageError, setEmployeePageError] = useState('')
  const personalKeyCursors = useRef(new Set<string>())
  const usageCursors = useRef(new Set<string>())
  const [createKeyOpen, setCreateKeyOpen] = useState(false)
  const [createKeyName, setCreateKeyName] = useState('')
  const [issuedKey, setIssuedKey] = useState<KeyIssuance | null>(null)
  const [revokeKey, setRevokeKey] = useState<PersonalKey | null>(null)
  const [logoutPending, setLogoutPending] = useState(false)
  const [logoutError, setLogoutError] = useState('')
  const navigationRef = useRef<HTMLElement>(null)
  const navigationTriggerRef = useRef<HTMLButtonElement>(null)
  const navigationCloseRef = useRef<HTMLButtonElement>(null)

  const criticalFaults = activeCriticalFaults(operationsHealth)
  const auditUnavailable = criticalFaults.includes('audit_unavailable')
  const operationsHealthPending = role === 'system_administrator' && operationsHealth === null

  function selectSection(label: string) {
    if (role === 'employee' && label !== 'Overview') {
      setEmployeeLoading(true)
      setEmployeeError('')
    }
    setActiveSection(label)
    setNavigationOpen(false)
    document.getElementById('main-content')?.focus()
  }

  function openNavigation() {
    setNavigationOpen(true)
    window.requestAnimationFrame(() => navigationCloseRef.current?.focus())
  }

  function closeNavigation() {
    setNavigationOpen(false)
    navigationTriggerRef.current?.focus()
  }

  function handleNavigationKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (!navigationOpen) return
    if (event.key === 'Escape') {
      event.preventDefault()
      event.stopPropagation()
      closeNavigation()
      return
    }
    if (navigationRef.current) trapTabKey(event, navigationRef.current)
  }

  useEffect(() => {
    if (role !== 'system_administrator') return
    let cancelled = false
    let inFlight = false

    async function refreshHealth() {
      if (inFlight) return
      inFlight = true
      try {
        const health = await adminClient.getOperationsHealth()
        if (!cancelled) setOperationsHealth(health)
      } catch {
        if (!cancelled) setOperationsHealth(databaseUnavailableHealth())
      } finally {
        inFlight = false
      }
    }

    void refreshHealth()
    const intervalID = window.setInterval(() => { void refreshHealth() }, 30_000)
    return () => {
      cancelled = true
      window.clearInterval(intervalID)
    }
  }, [adminClient, role])

  useEffect(() => {
    if (role !== 'employee' || activeSection === 'Overview') return
    let cancelled = false
    const seenCursors = new Set<string>()
    if (activeSection === 'My keys') personalKeyCursors.current = seenCursors
    else usageCursors.current = seenCursors
    const load = activeSection === 'My keys'
      ? employeeClient.listPersonalKeys().then((response) => {
        if (!cancelled) {
          setPersonalKeys(response.data)
          setPersonalKeyCursor(advanceCursor(response.pagination, seenCursors))
        }
      })
      : employeeClient.listUsage().then((response) => {
        if (!cancelled) {
          setUsageRecords(response.data)
          setUsageCursor(advanceCursor(response.pagination, seenCursors))
        }
      })
    load.catch(() => {
      if (!cancelled) setEmployeeError('Unable to load this workspace right now.')
    }).finally(() => {
      if (!cancelled) setEmployeeLoading(false)
    })
    return () => { cancelled = true }
  }, [activeSection, employeeClient, role])

  async function submitCreateKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!createKeyName.trim() || employeeSubmitting) return
    setEmployeeError('')
    setEmployeeSubmitting(true)
    try {
      const issuance = await employeeClient.createPersonalKey(createKeyName.trim())
      setIssuedKey(issuance)
      setCreateKeyName('')
      setCreateKeyOpen(false)
      setPersonalKeys((current) => [issuance.key, ...current])
    } catch {
      setEmployeeError('Unable to create this key.')
    } finally {
      setEmployeeSubmitting(false)
    }
  }

  async function confirmRevokeKey() {
    if (!revokeKey || employeeSubmitting) return
    setEmployeeSubmitting(true)
    try {
      await employeeClient.revokePersonalKey(revokeKey.id)
      setPersonalKeys((current) => current.map((key) => key.id === revokeKey.id ? { ...key, status: 'revoked', revoked_at: new Date().toISOString() } : key))
      setRevokeKey(null)
    } catch {
      setEmployeeError('Unable to revoke this key.')
    } finally {
      setEmployeeSubmitting(false)
    }
  }

  async function loadMoreKeys() {
    if (!personalKeyCursor || employeePageLoading) return
    setEmployeePageLoading(true)
    setEmployeePageError('')
    try {
      const response = await employeeClient.listPersonalKeys(personalKeyCursor)
      const nextCursor = advanceCursor(response.pagination, personalKeyCursors.current)
      setPersonalKeys((current) => [...current, ...response.data.filter((item) => !current.some((existing) => existing.id === item.id))])
      setPersonalKeyCursor(nextCursor)
    } catch (failure: unknown) {
      if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setPersonalKeyCursor(undefined)
      setEmployeePageError('Unable to load more personal keys.')
    } finally {
      setEmployeePageLoading(false)
    }
  }

  async function loadMoreUsage() {
    if (!usageCursor || employeePageLoading) return
    setEmployeePageLoading(true)
    setEmployeePageError('')
    try {
      const response = await employeeClient.listUsage(usageCursor)
      const nextCursor = advanceCursor(response.pagination, usageCursors.current)
      setUsageRecords((current) => [...current, ...response.data.filter((item) => !current.some((existing) => existing.id === item.id))])
      setUsageCursor(nextCursor)
    } catch (failure: unknown) {
      if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setUsageCursor(undefined)
      setEmployeePageError('Unable to load more usage records.')
    } finally {
      setEmployeePageLoading(false)
    }
  }

  function employeeSurface() {
    if (activeSection === 'My keys') {
      return (
        <section className="activity-section employee-surface" aria-labelledby="personal-keys-title">
          <div className="section-heading-row">
            <div><p className="section-kicker">Credentials</p><h2 id="personal-keys-title">Personal API keys</h2></div>
            <button className="button button-primary" type="button" onClick={() => setCreateKeyOpen(true)}>Create personal key</button>
          </div>
          {employeeLoading ? <p className="loading-state">Loading personal keys…</p> : employeeError ? <p className="error-state" role="alert">{employeeError}</p> : (
            <><div className="table-wrap" tabIndex={0}><table aria-label="Personal API keys"><thead><tr><th scope="col">Name</th><th scope="col">Prefix</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead><tbody>
              {personalKeys.length ? personalKeys.map((key) => <tr key={key.id}><td>{key.name}</td><td className="muted-cell">{key.prefix}</td><td>{key.status}</td><td className="muted-cell">{new Date(key.created_at).toLocaleDateString()}</td><td><button className="button button-secondary button-small" type="button" disabled={key.status !== 'active'} onClick={() => setRevokeKey(key)} aria-label={`Revoke ${key.name}`}>Revoke</button></td></tr>) : <tr><td colSpan={5} className="empty-row">No personal keys yet.</td></tr>}
            </tbody></table></div>{employeePageError && <p className="error-state" role="alert">{employeePageError}</p>}{personalKeyCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={employeePageLoading} onClick={() => void loadMoreKeys()}>{employeePageLoading ? 'Loading…' : 'Load more keys'}</button></div>}</>
          )}
        </section>
      )
    }
    return (
      <section className="activity-section employee-surface" aria-labelledby="personal-usage-title">
        <div className="section-heading-row"><div><p className="section-kicker">Content-free record</p><h2 id="personal-usage-title">Personal usage</h2></div></div>
        {employeeLoading ? <p className="loading-state">Loading usage…</p> : employeeError ? <p className="error-state" role="alert">{employeeError}</p> : <><div className="table-wrap" tabIndex={0}><table aria-label="Personal usage"><thead><tr><th scope="col">When</th><th scope="col">Model</th><th scope="col">Outcome</th><th scope="col">Tokens</th></tr></thead><tbody>{usageRecords.length ? usageRecords.map((record) => <tr key={record.id}><td className="muted-cell">{new Date(record.created_at).toLocaleString()}</td><td>{record.model_id}</td><td>{record.outcome}</td><td>{record.usage?.total_tokens ?? 'Unknown'}</td></tr>) : <tr><td colSpan={4} className="empty-row">No usage records yet.</td></tr>}</tbody></table></div>{employeePageError && <p className="error-state" role="alert">{employeePageError}</p>}{usageCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={employeePageLoading} onClick={() => void loadMoreUsage()}>{employeePageLoading ? 'Loading…' : 'Load more usage'}</button></div>}</>}
      </section>
    )
  }

  return (
    <div className={`app-shell${navigationOpen ? ' navigation-open' : ''}`}>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <aside ref={navigationRef} className="sidebar" aria-label="Workspace navigation" onKeyDown={handleNavigationKeyDown}>
        <div className="sidebar-brand">
          <div className="brand-icon" aria-hidden="true">
            <ShieldCheck size={20} strokeWidth={1.8} />
          </div>
          <div>
            <p className="brand-name">N-API-P</p>
            <p className="brand-caption">Governance gateway</p>
          </div>
          <button
            ref={navigationCloseRef}
            className="icon-button sidebar-close"
            type="button"
            aria-label="Close navigation"
            title="Close navigation"
            onClick={closeNavigation}
          >
            <PanelLeftClose size={18} />
          </button>
        </div>

        <nav className="primary-navigation" aria-label="Primary navigation">
          <p className="nav-label">Workspace</p>
          {profile.nav.map((item) => {
            const Icon = item.icon
            const active = activeSection === item.label
            return (
              <a
                className={`nav-link${active ? ' active' : ''}`}
                href={`#${item.label.toLowerCase().replaceAll(' ', '-')}`}
                key={item.label}
                aria-current={active ? 'page' : undefined}
                onClick={(event) => {
                  event.preventDefault()
                  selectSection(item.label)
                }}
              >
                <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
                <span>{item.label}</span>
                {active && <ChevronRight className="nav-current" size={15} aria-hidden="true" />}
              </a>
            )
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="status-chip">
            <span className={`status-dot${role !== 'system_administrator' || operationsHealthPending ? ' status-dot-checking' : criticalFaults.length ? ' status-dot-critical' : ''}`} aria-hidden="true" />
            <span>{role !== 'system_administrator' ? 'Gateway status unavailable' : criticalFaults.length ? 'Critical fault active' : operationsHealthPending ? 'Checking gateway' : 'Gateway operational'}</span>
          </div>
          <a className="support-link" href="#support">
            <CircleHelp size={17} strokeWidth={1.8} aria-hidden="true" />
            <span>Support</span>
          </a>
        </div>
      </aside>

      <div className="content-shell">
        <header className="topbar">
          <button
            ref={navigationTriggerRef}
            className="icon-button navigation-trigger"
            type="button"
            aria-label="Open navigation"
            title="Open navigation"
            onClick={openNavigation}
          >
            <Menu size={20} />
          </button>
          <div className="breadcrumb" aria-label="Current location">
            <span>{profile.eyebrow}</span>
            <ChevronRight size={14} aria-hidden="true" />
            <strong>{activeSection}</strong>
          </div>
          <div className="topbar-actions">
            <button className="icon-button" type="button" aria-label="View notifications" title="View notifications">
              <Bell size={19} />
              <span className="notification-dot" aria-hidden="true" />
            </button>
            <button
              className="profile-button"
              type="button"
              aria-label="Open session details"
              onClick={() => setSessionDialogOpen(true)}
            >
              <span className="avatar" aria-hidden="true">{identityEmail ? identityEmail.slice(0, 2).toUpperCase() : 'NA'}</span>
              <span className="profile-copy">
                <strong>{identityEmail || 'Current account'}</strong>
                <small>{roleName(role)}</small>
              </span>
              <ChevronRight className="profile-chevron" size={16} aria-hidden="true" />
            </button>
          </div>
        </header>

        <main id="main-content" className="workspace" aria-label="Administration workspace" tabIndex={-1}>
          <div className="workspace-inner">
            <header className="page-heading">
              <div>
                <p className="section-kicker">{profile.eyebrow}</p>
                <h1 id="page-title">{activeSection}</h1>
                <p className="page-description">{profile.description}</p>
              </div>
              <div className="role-marker">
                <span className="role-marker-label">Signed in as</span>
                <strong>{roleName(role)}</strong>
              </div>
            </header>

            {role === 'system_administrator' && <CriticalFaultBanners health={operationsHealth} />}

            {activeSection === 'Overview' ? (
              <>
                <section className="signal-row" aria-label="Gateway status">
                  <div className="signal-card signal-card-primary">
                    <div className="signal-icon" aria-hidden="true"><Activity size={18} /></div>
                    <div>
                      <p>Gateway status</p>
                      <strong>{role !== 'system_administrator' ? 'Not available' : criticalFaults.length ? 'Action required' : operationsHealthPending ? 'Checking' : 'Operational'}</strong>
                    </div>
                    <span className="signal-meta">{role !== 'system_administrator' ? 'Gateway health is restricted to system administrators' : criticalFaults.length ? `${criticalFaults.length} critical condition${criticalFaults.length === 1 ? '' : 's'}` : operationsHealthPending ? 'Loading current status' : 'No critical faults'}</span>
                  </div>
                  <div className="signal-card">
                    <div className="signal-icon signal-icon-blue" aria-hidden="true"><ShieldCheck size={18} /></div>
                    <div>
                      <p>Audit capture</p>
                      <strong>{role !== 'system_administrator' ? 'Not available' : auditUnavailable ? 'Unavailable' : operationsHealthPending ? 'Checking' : 'Healthy'}</strong>
                    </div>
                    <span className="signal-meta">{role !== 'system_administrator' ? 'Audit health is restricted to system administrators' : auditUnavailable ? 'Chat dispatch blocked' : operationsHealthPending ? 'Loading current status' : 'No active audit fault'}</span>
                  </div>
                  <div className="signal-card">
                    <div className="signal-icon signal-icon-amber" aria-hidden="true"><Boxes size={18} /></div>
                    <div>
                      <p>Policy</p>
                      <strong>{role === 'system_administrator' ? 'Global allowlist' : 'Not available'}</strong>
                    </div>
                    <span className="signal-meta">{role === 'system_administrator' ? 'Current policy is shown in Model policy' : 'No overview policy data is exposed for this role'}</span>
                  </div>
                </section>

                <section className="metrics-section" aria-labelledby="metrics-title">
                  <div className="section-heading-row">
                    <div>
                      <p className="section-kicker">At a glance</p>
                      <h2 id="metrics-title">Usage signals</h2>
                    </div>
                    <span className="timestamp">Live data only</span>
                  </div>
                  <p className="empty-state">No overview aggregates are available for this session.</p>
                </section>

                <section className="activity-section" aria-labelledby="activity-title">
                  <div className="section-heading-row activity-heading">
                    <div>
                      <p className="section-kicker">Content-free record</p>
                      <h2 id="activity-title">Recent activity</h2>
                    </div>
                  </div>
                  <div className="table-wrap" tabIndex={0}>
                    <table aria-label="Recent activity">
                      <thead>
                        <tr><th scope="col">When</th><th scope="col">Actor</th><th scope="col">Activity</th><th scope="col">Result</th></tr>
                      </thead>
                      <tbody>
                        <tr><td className="empty-row" colSpan={4}>Activity data is not available in this overview.</td></tr>
                      </tbody>
                    </table>
                  </div>
                </section>
              </>
            ) : role === 'employee' ? employeeSurface() : role === 'team_administrator' ? (
              <TeamWorkspace key={`${activeSection}:${(teamIDs ?? [teamID]).join('|')}`} section={activeSection} teamID={teamID} teamIDs={teamIDs} client={teamClient} />
            ) : activeSection === 'Security events' ? <SecurityEventsWorkspace client={adminClient} /> : activeSection === 'Investigations' ? <InvestigationWorkspace client={adminClient} /> : <SystemAdminWorkspace key={activeSection} section={activeSection} client={adminClient} />}
          </div>
        </main>
      </div>

      {navigationOpen && <button className="navigation-scrim" type="button" aria-label="Close navigation" onClick={closeNavigation} />}

      {sessionDialogOpen && (
        <ModalDialog ariaLabelledBy="session-dialog-title" onDismiss={() => setSessionDialogOpen(false)}>
            <div className="dialog-heading">
              <div>
                <p className="section-kicker">Current session</p>
                <h2 id="session-dialog-title">Session details</h2>
              </div>
              <button className="icon-button" type="button" aria-label="Close session details" title="Close session details" onClick={() => setSessionDialogOpen(false)}>
                <X size={18} />
              </button>
            </div>
            <dl className="session-details">
              <div><dt>Account</dt><dd>{identityEmail || 'Not available'}</dd></div>
              <div><dt>Role</dt><dd>{roleName(role)}</dd></div>
              <div><dt>Session</dt><dd>Internal network · active</dd></div>
            </dl>
            <div className="dialog-actions">
              <button className="button button-secondary" type="button" onClick={() => setSessionDialogOpen(false)}>Close</button>
              {onLogout && <button className="button button-danger" type="button" disabled={logoutPending} onClick={async () => {
                if (logoutPending) return
                setLogoutError('')
                setLogoutPending(true)
                try {
                  await onLogout()
                } catch {
                  setLogoutError('Unable to sign out right now.')
                } finally {
                  setLogoutPending(false)
                }
              }}>{logoutPending ? 'Signing out…' : 'Sign out'}</button>}
            </div>
            {logoutError && <p className="error-state" role="alert">{logoutError}</p>}
        </ModalDialog>
      )}

      {createKeyOpen && (
        <ModalDialog ariaLabelledBy="create-key-title" onDismiss={() => setCreateKeyOpen(false)}>
            <div className="dialog-heading"><div><p className="section-kicker">Credentials</p><h2 id="create-key-title">Create personal key</h2></div><button className="icon-button" type="button" aria-label="Close create key" title="Close create key" onClick={() => setCreateKeyOpen(false)}><X size={18} /></button></div>
            <form className="dialog-form" onSubmit={submitCreateKey}><label className="field-label" htmlFor="key-name">Key name</label><input id="key-name" name="key_name" aria-label="Key name" autoComplete="off" spellCheck={false} value={createKeyName} onChange={(event) => setCreateKeyName(event.target.value)} maxLength={128} required /><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setCreateKeyOpen(false)}>Cancel</button><button className="button button-primary" type="submit" disabled={employeeSubmitting}>{employeeSubmitting ? 'Creating…' : 'Create key'}</button></div></form>
        </ModalDialog>
      )}

      {issuedKey && (
        <ModalDialog ariaLabelledBy="issued-key-title"><div className="dialog-heading"><div><p className="section-kicker">One-time display</p><h2 id="issued-key-title">New personal key</h2></div></div><p className="credential-warning">Copy this credential now. It will not be shown again.</p><code className="credential-value">{issuedKey.credential.value}</code><div className="dialog-actions"><button className="button button-primary" type="button" onClick={() => setIssuedKey(null)}>I have saved this key</button></div></ModalDialog>
      )}

      {revokeKey && (
        <ModalDialog ariaLabelledBy="revoke-key-title" onDismiss={() => setRevokeKey(null)}><div className="dialog-heading"><div><p className="section-kicker">Destructive action</p><h2 id="revoke-key-title">Revoke personal key</h2></div><button className="icon-button" type="button" aria-label="Close revoke confirmation" title="Close revoke confirmation" onClick={() => setRevokeKey(null)}><X size={18} /></button></div><p className="credential-warning">Revoke <strong>{revokeKey.name}</strong>? Requests using this key will stop immediately.</p><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setRevokeKey(null)}>Cancel</button><button className="button button-danger" type="button" disabled={employeeSubmitting} onClick={confirmRevokeKey}>{employeeSubmitting ? 'Revoking…' : 'Confirm revoke'}</button></div></ModalDialog>
      )}
    </div>
  )
}

function databaseUnavailableHealth(): HealthResponse {
  const checkedAt = new Date().toISOString()
  return {
    state: 'unhealthy',
    components: [{ name: 'database_unavailable', state: 'unhealthy', detail_code: 'database_unavailable', checked_at: checkedAt }],
    checked_at: checkedAt,
  }
}
