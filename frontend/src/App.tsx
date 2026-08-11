import { useEffect, useState, type FormEvent } from 'react'
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
  Search,
  ServerCog,
  Settings2,
  ShieldCheck,
  UsersRound,
  X,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import { createEmployeePortalClient, type EmployeePortalClient, type KeyIssuance, type PersonalKey, type UsageRecord } from './employee-api'
import { TeamWorkspace } from './TeamWorkspace'
import { createTeamPortalClient, type TeamPortalClient } from './team-api'

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
      { label: 'Audit', icon: FileClock },
      { label: 'Operations', icon: Settings2 },
    ],
  },
}

const activityRows = [
  { time: '09:42', actor: 'Mira Chen', action: 'Viewed usage summary', result: 'Allowed' },
  { time: '09:18', actor: 'Gateway', action: 'Model policy check', result: 'Passed' },
  { time: '08:57', actor: 'Jon Bell', action: 'Key used for chat request', result: 'Captured' },
  { time: 'Yesterday', actor: 'Mira Chen', action: 'Session renewed', result: 'Allowed' },
]

const metricCards = [
  { value: '1,248', label: 'Requests today', detail: '+8.4% from yesterday', tone: 'green' },
  { value: '100%', label: 'Audit capture', detail: 'No persistence faults', tone: 'blue' },
  { value: '12', label: 'Models available', detail: 'Global allowlist', tone: 'amber' },
]

function roleName(role: Role): string {
  return roleProfiles[role].label
}

export function App({ role = 'system_administrator', employeeClient: injectedEmployeeClient, teamClient: injectedTeamClient, teamID = '' }: { role?: Role; employeeClient?: EmployeePortalClient; teamClient?: TeamPortalClient; teamID?: string }) {
  const profile = roleProfiles[role]
  const [activeSection, setActiveSection] = useState('Overview')
  const [navigationOpen, setNavigationOpen] = useState(false)
  const [sessionDialogOpen, setSessionDialogOpen] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [employeeClient] = useState(() => injectedEmployeeClient ?? createEmployeePortalClient())
  const [teamClient] = useState(() => injectedTeamClient ?? createTeamPortalClient())
  const [personalKeys, setPersonalKeys] = useState<PersonalKey[]>([])
  const [usageRecords, setUsageRecords] = useState<UsageRecord[]>([])
  const [personalKeyCursor, setPersonalKeyCursor] = useState<string | undefined>()
  const [usageCursor, setUsageCursor] = useState<string | undefined>()
  const [employeeLoading, setEmployeeLoading] = useState(false)
  const [employeeError, setEmployeeError] = useState('')
  const [createKeyOpen, setCreateKeyOpen] = useState(false)
  const [createKeyName, setCreateKeyName] = useState('')
  const [issuedKey, setIssuedKey] = useState<KeyIssuance | null>(null)
  const [revokeKey, setRevokeKey] = useState<PersonalKey | null>(null)

  const visibleActivity = activityRows.filter((row) => {
    const searchable = `${row.actor} ${row.action} ${row.result}`.toLowerCase()
    return searchable.includes(searchTerm.trim().toLowerCase())
  })

  function selectSection(label: string) {
    if (role === 'employee' && label !== 'Overview') {
      setEmployeeLoading(true)
      setEmployeeError('')
    }
    setActiveSection(label)
    setNavigationOpen(false)
  }

  function handleSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
  }

  useEffect(() => {
    if (role !== 'employee' || activeSection === 'Overview') return
    let cancelled = false
    const load = activeSection === 'My keys'
      ? employeeClient.listPersonalKeys().then((response) => {
        if (!cancelled) {
          setPersonalKeys(response.data)
          setPersonalKeyCursor(response.pagination.next_cursor)
        }
      })
      : employeeClient.listUsage().then((response) => {
        if (!cancelled) {
          setUsageRecords(response.data)
          setUsageCursor(response.pagination.next_cursor)
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
    if (!createKeyName.trim()) return
    setEmployeeError('')
    try {
      const issuance = await employeeClient.createPersonalKey(createKeyName.trim())
      setIssuedKey(issuance)
      setCreateKeyName('')
      setCreateKeyOpen(false)
      setPersonalKeys((current) => [issuance.key, ...current])
    } catch {
      setEmployeeError('Unable to create this key.')
    }
  }

  async function confirmRevokeKey() {
    if (!revokeKey) return
    try {
      await employeeClient.revokePersonalKey(revokeKey.id)
      setPersonalKeys((current) => current.map((key) => key.id === revokeKey.id ? { ...key, status: 'revoked', revoked_at: new Date().toISOString() } : key))
      setRevokeKey(null)
    } catch {
      setEmployeeError('Unable to revoke this key.')
    }
  }

  async function loadMoreKeys() {
    if (!personalKeyCursor) return
    const response = await employeeClient.listPersonalKeys(personalKeyCursor)
    setPersonalKeys((current) => [...current, ...response.data])
    setPersonalKeyCursor(response.pagination.next_cursor)
  }

  async function loadMoreUsage() {
    if (!usageCursor) return
    const response = await employeeClient.listUsage(usageCursor)
    setUsageRecords((current) => [...current, ...response.data])
    setUsageCursor(response.pagination.next_cursor)
  }

  function employeeSurface() {
    if (activeSection === 'My keys') {
      return (
        <section className="activity-section employee-surface" aria-labelledby="personal-keys-title">
          <div className="section-heading-row">
            <div><p className="section-kicker">Credentials</p><h2 id="personal-keys-title">Personal API keys</h2></div>
            <button className="button button-primary" type="button" onClick={() => setCreateKeyOpen(true)}>Create personal key</button>
          </div>
          {employeeLoading ? <p className="loading-state">Loading personal keys...</p> : employeeError ? <p className="error-state" role="alert">{employeeError}</p> : (
            <><div className="table-wrap"><table aria-label="Personal API keys"><thead><tr><th scope="col">Name</th><th scope="col">Prefix</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead><tbody>
              {personalKeys.length ? personalKeys.map((key) => <tr key={key.id}><td>{key.name}</td><td className="muted-cell">{key.prefix}</td><td>{key.status}</td><td className="muted-cell">{new Date(key.created_at).toLocaleDateString()}</td><td><button className="button button-secondary button-small" type="button" disabled={key.status !== 'active'} onClick={() => setRevokeKey(key)} aria-label={`Revoke ${key.name}`}>Revoke</button></td></tr>) : <tr><td colSpan={5} className="empty-row">No personal keys yet.</td></tr>}
            </tbody></table></div>{personalKeyCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" onClick={loadMoreKeys}>Load more keys</button></div>}</>
          )}
        </section>
      )
    }
    return (
      <section className="activity-section employee-surface" aria-labelledby="personal-usage-title">
        <div className="section-heading-row"><div><p className="section-kicker">Content-free record</p><h2 id="personal-usage-title">Personal usage</h2></div></div>
        {employeeLoading ? <p className="loading-state">Loading usage...</p> : employeeError ? <p className="error-state" role="alert">{employeeError}</p> : <><div className="table-wrap"><table aria-label="Personal usage"><thead><tr><th scope="col">When</th><th scope="col">Model</th><th scope="col">Outcome</th><th scope="col">Tokens</th></tr></thead><tbody>{usageRecords.length ? usageRecords.map((record) => <tr key={record.id}><td className="muted-cell">{new Date(record.created_at).toLocaleString()}</td><td>{record.model_id}</td><td>{record.outcome}</td><td>{record.usage?.total_tokens ?? 'Unknown'}</td></tr>) : <tr><td colSpan={4} className="empty-row">No usage records yet.</td></tr>}</tbody></table></div>{usageCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" onClick={loadMoreUsage}>Load more usage</button></div>}</>}
      </section>
    )
  }

  return (
    <div className={`app-shell${navigationOpen ? ' navigation-open' : ''}`}>
      <aside className="sidebar" aria-label="Workspace navigation">
        <div className="sidebar-brand">
          <div className="brand-icon" aria-hidden="true">
            <ShieldCheck size={20} strokeWidth={1.8} />
          </div>
          <div>
            <h1 className="brand-name">N-API-P</h1>
            <p className="brand-caption">Governance gateway</p>
          </div>
          <button
            className="icon-button sidebar-close"
            type="button"
            aria-label="Close navigation"
            title="Close navigation"
            onClick={() => setNavigationOpen(false)}
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
            <span className="status-dot" aria-hidden="true" />
            <span>Gateway operational</span>
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
            className="icon-button navigation-trigger"
            type="button"
            aria-label="Open navigation"
            title="Open navigation"
            onClick={() => setNavigationOpen(true)}
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
              <span className="avatar" aria-hidden="true">MC</span>
              <span className="profile-copy">
                <strong>Mira Chen</strong>
                <small>{roleName(role)}</small>
              </span>
              <ChevronRight className="profile-chevron" size={16} aria-hidden="true" />
            </button>
          </div>
        </header>

        <main className="workspace" aria-label="Administration workspace">
          <div className="workspace-inner">
            <section className="page-heading" aria-labelledby="page-title">
              <div>
                <p className="section-kicker">{profile.eyebrow}</p>
                <h2 id="page-title">{activeSection}</h2>
                <p className="page-description">{profile.description}</p>
              </div>
              <div className="role-marker">
                <span className="role-marker-label">Signed in as</span>
                <strong>{roleName(role)}</strong>
              </div>
            </section>

            {activeSection === 'Overview' ? (
              <>
                <section className="signal-row" aria-label="Gateway status">
                  <div className="signal-card signal-card-primary">
                    <div className="signal-icon" aria-hidden="true"><Activity size={18} /></div>
                    <div>
                      <p>Gateway status</p>
                      <strong>Operational</strong>
                    </div>
                    <span className="signal-meta">Updated 2 min ago</span>
                  </div>
                  <div className="signal-card">
                    <div className="signal-icon signal-icon-blue" aria-hidden="true"><ShieldCheck size={18} /></div>
                    <div>
                      <p>Audit capture</p>
                      <strong>Healthy</strong>
                    </div>
                    <span className="signal-meta">All requests recorded</span>
                  </div>
                  <div className="signal-card">
                    <div className="signal-icon signal-icon-amber" aria-hidden="true"><Boxes size={18} /></div>
                    <div>
                      <p>Policy</p>
                      <strong>Global allowlist</strong>
                    </div>
                    <span className="signal-meta">12 models available</span>
                  </div>
                </section>

                <section className="metrics-section" aria-labelledby="metrics-title">
                  <div className="section-heading-row">
                    <div>
                      <p className="section-kicker">At a glance</p>
                      <h2 id="metrics-title">Usage signals</h2>
                    </div>
                    <span className="timestamp">Today, 10:00 local time</span>
                  </div>
                  <div className="metric-grid">
                    {metricCards.map((metric) => (
                      <article className={`metric-card metric-card-${metric.tone}`} key={metric.label}>
                        <p>{metric.label}</p>
                        <strong>{metric.value}</strong>
                        <span>{metric.detail}</span>
                      </article>
                    ))}
                  </div>
                </section>

                <section className="activity-section" aria-labelledby="activity-title">
                  <div className="section-heading-row activity-heading">
                    <div>
                      <p className="section-kicker">Content-free record</p>
                      <h2 id="activity-title">Recent activity</h2>
                    </div>
                    <form className="search-form" role="search" onSubmit={handleSearch}>
                      <label className="field-label" htmlFor="activity-search">Search activity</label>
                      <div className="search-input-wrap">
                        <Search size={17} aria-hidden="true" />
                        <input
                          id="activity-search"
                          type="search"
                          value={searchTerm}
                          onChange={(event) => setSearchTerm(event.target.value)}
                          placeholder="Search by actor or action"
                          aria-label="Search administration"
                        />
                        {searchTerm && (
                          <button
                            className="clear-search"
                            type="button"
                            aria-label="Clear search"
                            title="Clear search"
                            onClick={() => setSearchTerm('')}
                          >
                            <X size={15} />
                          </button>
                        )}
                      </div>
                    </form>
                  </div>
                  <div className="table-wrap">
                    <table aria-label="Recent activity">
                      <thead>
                        <tr><th scope="col">When</th><th scope="col">Actor</th><th scope="col">Activity</th><th scope="col">Result</th></tr>
                      </thead>
                      <tbody>
                        {visibleActivity.length > 0 ? visibleActivity.map((row) => (
                          <tr key={`${row.time}-${row.action}`}>
                            <td className="muted-cell">{row.time}</td>
                            <td>{row.actor}</td>
                            <td>{row.action}</td>
                            <td><span className="result-tag"><span className="status-dot" aria-hidden="true" />{row.result}</span></td>
                          </tr>
                        )) : (
                          <tr><td className="empty-row" colSpan={4}>No activity matches this search.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </section>
              </>
            ) : role === 'employee' ? employeeSurface() : role === 'team_administrator' ? (
              <TeamWorkspace section={activeSection} teamID={teamID} client={teamClient} />
            ) : (
              <section className="empty-surface" aria-labelledby="section-title">
                <div className="empty-icon" aria-hidden="true"><Settings2 size={22} /></div>
                <h2 id="section-title">{activeSection}</h2>
                <p>This work surface is ready for its separately scoped workflow.</p>
              </section>
            )}
          </div>
        </main>
      </div>

      {navigationOpen && <button className="navigation-scrim" type="button" aria-label="Close navigation" onClick={() => setNavigationOpen(false)} />}

      {sessionDialogOpen && (
        <div className="dialog-backdrop" role="presentation">
          <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="session-dialog-title">
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
              <div><dt>Account</dt><dd>mira.chen@company.internal</dd></div>
              <div><dt>Role</dt><dd>{roleName(role)}</dd></div>
              <div><dt>Session</dt><dd>Internal network · active</dd></div>
            </dl>
            <div className="dialog-actions">
              <button className="button button-secondary" type="button" onClick={() => setSessionDialogOpen(false)}>Close</button>
            </div>
          </section>
        </div>
      )}

      {createKeyOpen && (
        <div className="dialog-backdrop" role="presentation">
          <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="create-key-title">
            <div className="dialog-heading"><div><p className="section-kicker">Credentials</p><h2 id="create-key-title">Create personal key</h2></div><button className="icon-button" type="button" aria-label="Close create key" title="Close create key" onClick={() => setCreateKeyOpen(false)}><X size={18} /></button></div>
            <form className="dialog-form" onSubmit={submitCreateKey}><label className="field-label" htmlFor="key-name">Key name</label><input id="key-name" aria-label="Key name" value={createKeyName} onChange={(event) => setCreateKeyName(event.target.value)} maxLength={128} required /><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setCreateKeyOpen(false)}>Cancel</button><button className="button button-primary" type="submit">Create key</button></div></form>
          </section>
        </div>
      )}

      {issuedKey && (
        <div className="dialog-backdrop" role="presentation">
          <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="issued-key-title"><div className="dialog-heading"><div><p className="section-kicker">One-time display</p><h2 id="issued-key-title">New personal key</h2></div></div><p className="credential-warning">Copy this credential now. It will not be shown again.</p><code className="credential-value">{issuedKey.credential.value}</code><div className="dialog-actions"><button className="button button-primary" type="button" onClick={() => setIssuedKey(null)}>I have saved this key</button></div></section>
        </div>
      )}

      {revokeKey && (
        <div className="dialog-backdrop" role="presentation">
          <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="revoke-key-title"><div className="dialog-heading"><div><p className="section-kicker">Destructive action</p><h2 id="revoke-key-title">Revoke personal key</h2></div><button className="icon-button" type="button" aria-label="Close revoke confirmation" title="Close revoke confirmation" onClick={() => setRevokeKey(null)}><X size={18} /></button></div><p className="credential-warning">Revoke <strong>{revokeKey.name}</strong>? Requests using this key will stop immediately.</p><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setRevokeKey(null)}>Cancel</button><button className="button button-danger" type="button" onClick={confirmRevokeKey}>Confirm revoke</button></div></section>
        </div>
      )}
    </div>
  )
}
