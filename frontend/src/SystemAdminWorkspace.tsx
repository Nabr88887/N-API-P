import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { AdminAPIError } from './admin-api'
import type { Account, AdminPortalClient, Key, Model, Pagination, RetentionPolicy, ServiceAccount, Team } from './admin-api'
import { AuditWorkspace } from './AuditWorkspace'
import { ModalDialog } from './ModalDialog'
import { OperationsWorkspace } from './OperationsWorkspace'
import { SecurityEventsWorkspace } from './SecurityEventsWorkspace'
import { advanceCursor, collectAllPages } from './pagination'

type Props = { section: string; client: AdminPortalClient }
type OneTimeCredential = { title: string; value: string }

export function SystemAdminWorkspace({ section, client }: Props) {
  const [accounts, setAccounts] = useState<Account[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [services, setServices] = useState<ServiceAccount[]>([])
	const [accountPagination, setAccountPagination] = useState<Pagination>({ has_more: false })
	const [teamPagination, setTeamPagination] = useState<Pagination>({ has_more: false })
	const [servicePagination, setServicePagination] = useState<Pagination>({ has_more: false })
	const [keyPagination, setKeyPagination] = useState<Pagination>({ has_more: false })
	const [accountPageLoading, setAccountPageLoading] = useState(false)
	const [teamPageLoading, setTeamPageLoading] = useState(false)
	const [servicePageLoading, setServicePageLoading] = useState(false)
	const [keyPageLoading, setKeyPageLoading] = useState(false)
	const [paginationError, setPaginationError] = useState('')
  const accountCursors = useRef(new Set<string>())
  const teamCursors = useRef(new Set<string>())
  const serviceCursors = useRef(new Set<string>())
  const keyCursors = useRef(new Set<string>())
  const [keys, setKeys] = useState<Key[]>([])
  const [models, setModels] = useState<Model[]>([])
	const [modelID, setModelID] = useState('')
  const [retention, setRetention] = useState<RetentionPolicy | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [mutationPending, setMutationPending] = useState(false)
  const [inviteOpen, setInviteOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteTeam, setInviteTeam] = useState('')
  const [credential, setCredential] = useState<OneTimeCredential | null>(null)
  const [resetTarget, setResetTarget] = useState<Account | null>(null)
  const [manualVerified, setManualVerified] = useState(false)
  const [compromise, setCompromise] = useState(false)
  const [reauthOpen, setReauthOpen] = useState(false)
  const [reauthPassword, setReauthPassword] = useState('')
  const [keyService, setKeyService] = useState<ServiceAccount | null>(null)
	const [serviceCreateOpen, setServiceCreateOpen] = useState(false)
	const [serviceName, setServiceName] = useState('')
	const [serviceTeam, setServiceTeam] = useState('')
	const [serviceOwner, setServiceOwner] = useState('')
  const [keyName, setKeyName] = useState('')
  const [keyCreateOpen, setKeyCreateOpen] = useState(false)
  const [rotateKey, setRotateKey] = useState<Key | null>(null)
  const [rotateName, setRotateName] = useState('')
  const [revokeKey, setRevokeKey] = useState<Key | null>(null)
  const [accessTarget, setAccessTarget] = useState<Account | null>(null)
  const [accessRole, setAccessRole] = useState<Account['role']>('employee')
  const [accessTeam, setAccessTeam] = useState('')
  const [accessEmail, setAccessEmail] = useState('')
  const [accessError, setAccessError] = useState('')
  const [confirmation, setConfirmation] = useState<{ title: string; action: string; run: () => Promise<void> } | null>(null)
  const [modelConfirm, setModelConfirm] = useState(false)
  const [modelValidationError, setModelValidationError] = useState('')
  const [retentionDays, setRetentionDays] = useState(7)
  const [retentionConfirm, setRetentionConfirm] = useState(false)
  const pendingSensitiveAction = useRef<null | (() => Promise<void>)>(null)

  useEffect(() => {
    let cancelled = false
    if (section === 'People & teams') {
      accountCursors.current = new Set<string>()
      teamCursors.current = new Set<string>()
    } else if (section === 'Service accounts') {
      serviceCursors.current = new Set<string>()
    }
    const load = section === 'People & teams'
	  ? Promise.all([client.listAccounts(), client.listTeams()]).then(([accountPage, teamPage]) => { if (!cancelled) { setAccounts(accountPage.data); setAccountPagination({ ...accountPage.pagination, next_cursor: advanceCursor(accountPage.pagination, accountCursors.current) }); setTeams(teamPage.data); setTeamPagination({ ...teamPage.pagination, next_cursor: advanceCursor(teamPage.pagination, teamCursors.current) }) } })
      : section === 'Service accounts'
		? Promise.all([client.listServiceAccounts(), listAllTeams(client), listAllEmployees(client)]).then(([servicePage, activeTeams, activeEmployees]) => { if (!cancelled) { setServices(servicePage.data); setServicePagination({ ...servicePage.pagination, next_cursor: advanceCursor(servicePage.pagination, serviceCursors.current) }); setTeams(activeTeams); setAccounts(activeEmployees) } })
        : section === 'Model policy'
          ? client.getModelAllowlist().then((response) => { if (!cancelled) setModels(response.data) })
          : section === 'Retention'
            ? client.getRetentionPolicy().then((policy) => { if (!cancelled) { setRetention(policy); setRetentionDays(policy.days) } })
            : Promise.resolve()
    load.catch((reason: unknown) => { if (!cancelled) setError(errorCode(reason) === 'REAUTHENTICATION_REQUIRED' ? 'Recent password reauthentication is required.' : 'Unable to load this workspace right now.') }).finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [client, section])

	async function loadMoreAccounts() {
		if (!accountPagination.next_cursor || accountPageLoading) return
		setAccountPageLoading(true); setPaginationError('')
		try {
			const page = await client.listAccounts({ cursor: accountPagination.next_cursor })
			const nextCursor = advanceCursor(page.pagination, accountCursors.current)
			setAccounts((current) => appendUnique(current, page.data))
			setAccountPagination({ ...page.pagination, next_cursor: nextCursor })
		} catch (failure: unknown) { if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setAccountPagination({ has_more: false }); setPaginationError('Unable to load more accounts.') } finally { setAccountPageLoading(false) }
	}

	async function loadMoreTeams() {
		if (!teamPagination.next_cursor || teamPageLoading) return
		setTeamPageLoading(true); setPaginationError('')
		try {
			const page = await client.listTeams({ cursor: teamPagination.next_cursor })
			const nextCursor = advanceCursor(page.pagination, teamCursors.current)
			setTeams((current) => appendUnique(current, page.data))
			setTeamPagination({ ...page.pagination, next_cursor: nextCursor })
		} catch (failure: unknown) { if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setTeamPagination({ has_more: false }); setPaginationError('Unable to load more teams.') } finally { setTeamPageLoading(false) }
	}

	async function loadMoreServices() {
		if (!servicePagination.next_cursor || servicePageLoading) return
		setServicePageLoading(true); setPaginationError('')
		try {
			const page = await client.listServiceAccounts({ cursor: servicePagination.next_cursor })
			const nextCursor = advanceCursor(page.pagination, serviceCursors.current)
			setServices((current) => appendUnique(current, page.data))
			setServicePagination({ ...page.pagination, next_cursor: nextCursor })
		} catch (failure: unknown) { if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setServicePagination({ has_more: false }); setPaginationError('Unable to load more service accounts.') } finally { setServicePageLoading(false) }
	}

  async function submitInvite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!inviteEmail.trim() || !inviteTeam) return
    if (mutationPending) return
    setMutationPending(true)
    try { const response = await client.invite(inviteEmail.trim(), inviteTeam); setCredential({ title: 'New invitation', value: response.activation_code }); setInviteOpen(false); setInviteEmail('') } catch { setError('Unable to create this invitation.') } finally { setMutationPending(false) }
  }

  async function issueReset() {
    if (!resetTarget || !manualVerified || mutationPending) return
    setMutationPending(true)
    try { const response = await client.issuePasswordReset(resetTarget.id, resetTarget.email, manualVerified, compromise); setCredential({ title: 'New password reset value', value: response.code }); setResetTarget(null); setManualVerified(false); setCompromise(false) } catch (reason: unknown) { if (errorCode(reason) === 'REAUTHENTICATION_REQUIRED') { pendingSensitiveAction.current = issueReset; setReauthOpen(true) } else setError('Unable to issue this reset value.') }
    finally { setMutationPending(false) }
  }

  async function finishReauth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (mutationPending) return
    setMutationPending(true)
    try { await client.reauthenticate(reauthPassword); setReauthOpen(false); setReauthPassword(''); const action = pendingSensitiveAction.current; pendingSensitiveAction.current = null; setMutationPending(false); if (action) await action() } catch { setError('Reauthentication failed.') }
    finally { setMutationPending(false) }
  }

  async function createGroupKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!keyService || !keyName.trim()) return
    if (mutationPending) return
    setMutationPending(true)
    try { const response = await client.createServiceKey(keyService.id, keyName.trim()); setCredential({ title: 'New group key', value: response.credential.value }); setKeys((current) => [response.key, ...current]); setKeyName(''); setKeyCreateOpen(false) } catch { setError('Unable to create this group key.') } finally { setMutationPending(false) }
  }

	async function manageKeys(service: ServiceAccount) {
	setKeyService(service); setKeys([]); setKeyPagination({ has_more: false }); keyCursors.current = new Set<string>(); setPaginationError(''); setError('')
	try { const response = await client.listServiceKeys(service.id); setKeys(response.data); setKeyPagination({ ...response.pagination, next_cursor: advanceCursor(response.pagination, keyCursors.current) }) } catch { setError('Unable to load group keys.') }
	}

  async function loadMoreKeys() {
	if (!keyService || !keyPagination.next_cursor || keyPageLoading) return
	setKeyPageLoading(true); setPaginationError('')
	try {
		const page = await client.listServiceKeys(keyService.id, { cursor: keyPagination.next_cursor })
		const nextCursor = advanceCursor(page.pagination, keyCursors.current)
		setKeys((current) => appendUnique(current, page.data))
		setKeyPagination({ ...page.pagination, next_cursor: nextCursor })
	} catch (failure: unknown) { if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setKeyPagination({ has_more: false }); setPaginationError('Unable to load more group keys.') } finally { setKeyPageLoading(false) }
  }

  async function confirmRotateKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!keyService || !rotateKey || !rotateName.trim()) return
    if (mutationPending) return
    setMutationPending(true)
    try { const response = await client.rotateServiceKey(keyService.id, rotateKey.id, rotateName.trim()); setCredential({ title: 'New group key', value: response.credential.value }); setKeys((current) => [response.key, ...current.map((item) => item.id === rotateKey.id ? { ...item, status: 'revoked' as const } : item)]); setRotateKey(null); setRotateName('') } catch { setError('Unable to rotate this group key.') } finally { setMutationPending(false) }
  }

  async function confirmRevokeKey() {
    if (!keyService || !revokeKey || mutationPending) return
    setMutationPending(true)
    try { await client.revokeServiceKey(keyService.id, revokeKey.id); setKeys((current) => current.map((item) => item.id === revokeKey.id ? { ...item, status: 'revoked' as const } : item)); setRevokeKey(null) } catch { setError('Unable to revoke this group key.') } finally { setMutationPending(false) }
  }

	function openServiceCreate() {
		const teamID = teams[0]?.id ?? ''
		setServiceTeam(teamID)
		setServiceOwner(serviceOwners(teamID)[0]?.id ?? '')
		setServiceCreateOpen(true)
	}

	function serviceOwners(teamID: string) {
		return accounts.filter((account) => account.team_ids?.includes(teamID))
	}

	function selectServiceTeam(teamID: string) {
		setServiceTeam(teamID)
		setServiceOwner(serviceOwners(teamID)[0]?.id ?? '')
	}

  async function createServiceAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!serviceName.trim() || !serviceTeam || !serviceOwner) return
    if (mutationPending) return
    setMutationPending(true)
    try {
			const account = await client.createServiceAccount(serviceTeam, serviceOwner, serviceName.trim())
			setServices((current) => [account, ...current])
			setServiceName('')
			setServiceCreateOpen(false)
    } catch { setError('Unable to create this service account.') } finally { setMutationPending(false) }
	}

	async function disableServiceAccount(account: ServiceAccount) {
		if (mutationPending) return
		setMutationPending(true)
		try { await client.disableServiceAccount(account.id)
		setServices((current) => current.map((item) => item.id === account.id ? { ...item, status: 'disabled' as const } : item))
		setConfirmation(null)
		} finally { setMutationPending(false) }
	}

	function manageAccess(account: Account) {
    setAccessTarget(account); setAccessRole(account.role); setAccessTeam(account.team_ids?.[0] ?? teams[0]?.id ?? ''); setAccessEmail(account.email); setAccessError('')
  }

  async function updateEmail() {
    if (!accessTarget || !accessEmail.trim() || mutationPending) return
    setMutationPending(true)
    setAccessError('')
    try {
      await client.updateAccount(accessTarget.id, { email: accessEmail.trim() })
      setAccessTarget((current) => current ? { ...current, email: accessEmail.trim() } : current)
      setAccounts((current) => current.map((account) => account.id === accessTarget.id ? { ...account, email: accessEmail.trim() } : account))
    } catch {
      setAccessError('Unable to update this email.')
    } finally {
      setMutationPending(false)
    }
  }

  async function applyRole() {
    if (!accessTarget || mutationPending) return
    setMutationPending(true)
    try {
    await client.updateAccount(accessTarget.id, { role: accessRole, confirmed: true })
    setAccounts((current) => current.map((account) => account.id === accessTarget.id ? { ...account, role: accessRole } : account))
    setConfirmation(null)
    } finally { setMutationPending(false) }
  }

  async function addMembership() {
    if (!accessTarget || !accessTeam || mutationPending) return
    setMutationPending(true)
    try {
    await client.addMember(accessTeam, accessTarget.id)
    setAccounts((current) => current.map((account) => account.id === accessTarget.id ? { ...account, team_ids: Array.from(new Set([...(account.team_ids ?? []), accessTeam])) } : account))
    } finally { setMutationPending(false) }
  }

  async function removeMembership() {
    if (!accessTarget || !accessTeam || mutationPending) return
    setMutationPending(true)
    try {
    await client.removeMember(accessTeam, accessTarget.id)
    setAccounts((current) => current.map((account) => account.id === accessTarget.id ? { ...account, team_ids: account.team_ids?.filter((id) => id !== accessTeam) } : account))
    setConfirmation(null)
    } finally { setMutationPending(false) }
  }

  async function disableAccount() {
    if (!accessTarget || mutationPending) return
    setMutationPending(true)
    try {
    await client.updateAccount(accessTarget.id, { status: 'disabled', confirmed: true })
    setAccounts((current) => current.map((account) => account.id === accessTarget.id ? { ...account, status: 'disabled' as const } : account))
    setConfirmation(null); setAccessTarget(null)
    } finally { setMutationPending(false) }
  }

	async function disableTeam(team: Team) {
		if (mutationPending) return
		setMutationPending(true)
		try { await client.disableTeam(team.id)
		setTeams((current) => current.map((item) => item.id === team.id ? { ...item, status: 'disabled' as const } : item))
		setConfirmation(null)
		} finally { setMutationPending(false) }
	}

  async function saveModels() {
    if (mutationPending) return
    setMutationPending(true)
    try { const response = await client.replaceModelAllowlist(models, true); setModels(response.data); setModelConfirm(false) } catch (reason: unknown) { if (errorCode(reason) === 'REAUTHENTICATION_REQUIRED') { pendingSensitiveAction.current = saveModels; setModelConfirm(false); setReauthOpen(true) } else setError('Unable to save the model policy.') } finally { setMutationPending(false) }
  }

  function openModelConfirm() {
    if (models.some((model) => !validPricing(model))) {
      setModelValidationError('Model pricing must use a complete non-negative decimal tuple with a non-blank version.')
      return
    }
    setModelValidationError('')
    setModelConfirm(true)
  }

	function addModel(event: FormEvent<HTMLFormElement>) {
		event.preventDefault()
		const id = modelID.trim()
		if (!id || models.some((model) => model.id === id)) return
		setModels((current) => [...current, { id, status: 'allowed', updated_at: new Date().toISOString() }])
		setModelID('')
	}

  async function saveRetention() {
    if (mutationPending) return
    setMutationPending(true)
    try { const response = await client.replaceRetentionPolicy(retentionDays, true); setRetention(response); setRetentionConfirm(false) } catch (reason: unknown) { if (errorCode(reason) === 'REAUTHENTICATION_REQUIRED') { pendingSensitiveAction.current = saveRetention; setRetentionConfirm(false); setReauthOpen(true) } else setError('Unable to save retention policy.') } finally { setMutationPending(false) }
  }

  let surface: ReactNode
  if (loading) surface = <section className="activity-section" aria-label={section}><p className="loading-state">Loading {section.toLowerCase()}…</p></section>
  else if (error) surface = <section className="activity-section" aria-label={section}><p className="error-state" role="alert">{error}</p></section>
  else if (section === 'People & teams') surface = <>
	<section className="activity-section" aria-labelledby="accounts-title"><div className="section-heading-row"><div><p className="section-kicker">Access control</p><h2 id="accounts-title">Accounts</h2></div><button className="button button-primary" type="button" disabled={!teams.some((team) => team.status === 'active')} onClick={() => { setInviteTeam(teams.find((team) => team.status === 'active')?.id ?? ''); setInviteOpen(true) }}>Invite employee</button></div><div className="table-wrap" tabIndex={0}><table aria-label="Accounts"><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Teams</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{accounts.map((account) => <tr key={account.id}><td>{account.email}</td><td>{account.role.replace('_', ' ')}</td><td>{account.status}</td><td>{account.team_ids?.join(', ') || 'None'}</td><td><div className="row-actions"><button className="button button-secondary button-small" type="button" onClick={() => manageAccess(account)} aria-label={`Manage access for ${account.email}`}>Access</button>{account.role === 'employee' && account.status === 'active' && <button className="button button-secondary button-small" type="button" onClick={() => setResetTarget(account)} aria-label={`Recover ${account.email}`}>Recover</button>}</div></td></tr>)}</tbody></table></div>{accountPagination.has_more && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={accountPageLoading} onClick={() => void loadMoreAccounts()}>{accountPageLoading ? 'Loading…' : 'Load more accounts'}</button></div>}</section>
	<section className="activity-section" aria-labelledby="teams-title"><div className="section-heading-row"><div><p className="section-kicker">Membership</p><h2 id="teams-title">Teams</h2></div></div><div className="table-wrap" tabIndex={0}><table aria-label="Teams"><thead><tr><th>Name</th><th>Status</th><th>Members</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{teams.map((team) => <tr key={team.id}><td>{team.name}</td><td>{team.status}</td><td>{team.member_count}</td><td><button className="button button-secondary button-small" type="button" disabled={team.status === 'disabled'} onClick={() => setConfirmation({ title: 'Disable team', action: 'Disable team', run: () => disableTeam(team) })} aria-label={`Disable ${team.name}`}>Disable</button></td></tr>)}</tbody></table></div>{teamPagination.has_more && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={teamPageLoading} onClick={() => void loadMoreTeams()}>{teamPageLoading ? 'Loading…' : 'Load more teams'}</button></div>}</section>
  </>
	else if (section === 'Service accounts') surface = <section className="activity-section" aria-labelledby="service-accounts-title"><div className="section-heading-row"><div><p className="section-kicker">Non-human access</p><h2 id="service-accounts-title">Service accounts</h2></div><button className="button button-primary" type="button" onClick={openServiceCreate}>Create service account</button></div><div className="table-wrap" tabIndex={0}><table aria-label="Service accounts"><thead><tr><th>Name</th><th>Team</th><th>Responsible employee</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{services.map((service) => <tr key={service.id}><td>{service.name}</td><td>{service.team_id}</td><td>{service.responsible_account_id}</td><td>{service.status}</td><td><div className="row-actions"><button className="button button-secondary button-small" type="button" onClick={() => void manageKeys(service)} aria-label={`Manage keys for ${service.name}`}>Manage keys</button><button className="button button-secondary button-small" type="button" disabled={service.status === 'disabled'} onClick={() => setConfirmation({ title: 'Disable service account', action: 'Disable service account', run: () => disableServiceAccount(service) })} aria-label={`Disable ${service.name}`}>Disable</button></div></td></tr>)}</tbody></table></div>{servicePagination.has_more && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={servicePageLoading} onClick={() => void loadMoreServices()}>{servicePageLoading ? 'Loading…' : 'Load more service accounts'}</button></div>}</section>
  else if (section === 'Model policy') surface = <section className="activity-section" aria-labelledby="model-policy-title"><div className="section-heading-row"><div><p className="section-kicker">Global control</p><h2 id="model-policy-title">Global model allowlist</h2></div><button className="button button-primary" type="button" onClick={openModelConfirm}>Save model policy</button></div>{modelValidationError && <p className="error-state" role="alert">{modelValidationError}</p>}<form className="policy-form model-add-form" onSubmit={addModel}><label className="field-label" htmlFor="model-id">Model ID</label><input id="model-id" name="model_id" aria-label="Model ID" autoComplete="off" spellCheck={false} value={modelID} onChange={(event) => setModelID(event.target.value)} required /><button className="button button-secondary" type="submit">Add model</button></form><div className="table-wrap" tabIndex={0}><table aria-label="Global model allowlist"><thead><tr><th>Model</th><th>Status</th><th>Input unit price</th><th>Output unit price</th><th>Price version</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{models.length ? models.map((model) => <tr key={model.id}><td>{model.id}</td><td><select aria-label={`Status for ${model.id}`} value={model.status} onChange={(event) => setModels((current) => current.map((item) => item.id === model.id ? { ...item, status: event.target.value as Model['status'] } : item))}><option value="allowed">allowed</option><option value="disabled">disabled</option></select></td><td><input aria-label={`Input unit price for ${model.id}`} inputMode="decimal" value={model.input_unit_price ?? ''} onChange={(event) => setModels((current) => current.map((item) => item.id === model.id ? { ...item, input_unit_price: event.target.value } : item))} /></td><td><input aria-label={`Output unit price for ${model.id}`} inputMode="decimal" value={model.output_unit_price ?? ''} onChange={(event) => setModels((current) => current.map((item) => item.id === model.id ? { ...item, output_unit_price: event.target.value } : item))} /></td><td><input aria-label={`Price version for ${model.id}`} value={model.price_version ?? ''} onChange={(event) => setModels((current) => current.map((item) => item.id === model.id ? { ...item, price_version: event.target.value } : item))} /></td><td><button className="button button-secondary button-small" type="button" onClick={() => setModels((current) => current.filter((item) => item.id !== model.id))} aria-label={`Remove ${model.id}`}>Remove</button></td></tr>) : <tr><td className="empty-row" colSpan={6}>No models configured.</td></tr>}</tbody></table></div>{modelConfirm && <ConfirmationDialog title="Confirm model policy" action="Confirm model policy change" onCancel={() => setModelConfirm(false)} onConfirm={() => void saveModels()} />}</section>
  else if (section === 'Retention') surface = <section className="activity-section" aria-labelledby="retention-title"><div className="section-heading-row"><div><p className="section-kicker">Audit content</p><h2 id="retention-title">Retention</h2></div></div><div className="policy-form"><label className="field-label" htmlFor="retention-days">Raw content retention days</label><input id="retention-days" aria-label="Raw content retention days" type="number" min={1} max={retention?.maximum_days || 30} value={retentionDays} onChange={(event) => setRetentionDays(Number(event.target.value))} /><button className="button button-primary" type="button" onClick={() => setRetentionConfirm(true)}>Save retention policy</button></div>{retentionConfirm && <ConfirmationDialog title="Confirm retention change" action="Confirm retention change" onCancel={() => setRetentionConfirm(false)} onConfirm={() => void saveRetention()} />}</section>
  else if (section === 'Audit') surface = <AuditWorkspace client={client} />
  else if (section === 'Security events') surface = <SecurityEventsWorkspace client={client} />
  else if (section === 'Operations') surface = <OperationsWorkspace client={client} />
  else surface = <section className="empty-surface" aria-labelledby="section-title"><h2 id="section-title">{section}</h2><p>This workflow is separately scoped to a later administration task.</p></section>

	return <>{surface}{paginationError && <p className="error-state pagination-error" role="alert">{paginationError}</p>}
    {inviteOpen && <ModalDialog ariaLabelledBy="invite-title" onDismiss={() => setInviteOpen(false)}><div className="dialog-heading"><h2 id="invite-title">Invite employee</h2></div><form className="dialog-form" onSubmit={submitInvite}><label className="field-label" htmlFor="invite-email">Company email</label><input id="invite-email" name="company_email" aria-label="Company email" type="email" autoComplete="email" spellCheck={false} value={inviteEmail} onChange={(event) => setInviteEmail(event.target.value)} required /><label className="field-label" htmlFor="invite-team">Assigned team</label><select id="invite-team" name="team_id" aria-label="Assigned team" value={inviteTeam} onChange={(event) => setInviteTeam(event.target.value)} required>{teams.filter((team) => team.status === 'active').map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}</select><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setInviteOpen(false)}>Cancel</button><button className="button button-primary" type="submit" disabled={mutationPending}>{mutationPending ? 'Creating…' : 'Create invitation'}</button></div></form></ModalDialog>}
    {serviceCreateOpen && <ModalDialog ariaLabelledBy="service-create-title" onDismiss={() => setServiceCreateOpen(false)}><div className="dialog-heading"><h2 id="service-create-title">Create service account</h2></div><form className="dialog-form" onSubmit={createServiceAccount}><label className="field-label" htmlFor="service-name">Service account name</label><input id="service-name" name="service_account_name" aria-label="Service account name" autoComplete="off" spellCheck={false} value={serviceName} onChange={(event) => setServiceName(event.target.value)} required /><label className="field-label" htmlFor="service-team">Team</label><select id="service-team" name="team_id" aria-label="Service account team" value={serviceTeam} onChange={(event) => selectServiceTeam(event.target.value)} required>{teams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}</select><label className="field-label" htmlFor="service-owner">Responsible employee</label><select id="service-owner" name="responsible_account_id" aria-label="Responsible employee" value={serviceOwner} onChange={(event) => setServiceOwner(event.target.value)} required>{serviceOwners(serviceTeam).length ? serviceOwners(serviceTeam).map((account) => <option key={account.id} value={account.id}>{account.email}</option>) : <option value="">No eligible employee</option>}</select><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setServiceCreateOpen(false)}>Cancel</button><button className="button button-primary" type="submit" disabled={!serviceOwner || mutationPending}>{mutationPending ? 'Creating…' : 'Create account'}</button></div></form></ModalDialog>}
    {resetTarget && <ModalDialog ariaLabelledBy="reset-title" onDismiss={() => setResetTarget(null)}><div className="dialog-heading"><h2 id="reset-title">Assisted password recovery</h2></div><p className="credential-warning">Issue a single-use reset value for {resetTarget.email}.</p><label className="check-row"><input name="manual_verification" type="checkbox" checked={manualVerified} onChange={(event) => setManualVerified(event.target.checked)} />Manual identity verification completed</label><label className="check-row"><input name="compromise_response" type="checkbox" checked={compromise} onChange={(event) => setCompromise(event.target.checked)} />Treat as credential compromise</label><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setResetTarget(null)}>Cancel</button><button className="button button-primary" type="button" disabled={!manualVerified || mutationPending} onClick={() => void issueReset()}>{mutationPending ? 'Issuing…' : 'Issue reset value'}</button></div></ModalDialog>}
    {accessTarget && <ModalDialog ariaLabelledBy="access-title" className="dialog-wide" onDismiss={() => setAccessTarget(null)}><div className="dialog-heading"><h2 id="access-title">Manage access</h2></div><p className="credential-warning">{accessTarget.email}</p>{accessError && <p className="error-state" role="alert">{accessError}</p>}<div className="control-grid"><label className="field-label" htmlFor="access-email">Company email</label><input id="access-email" type="email" aria-label="Company email" value={accessEmail} onChange={(event) => setAccessEmail(event.target.value)} /><button className="button button-secondary" type="button" disabled={mutationPending || !accessEmail.trim()} onClick={() => void updateEmail()}>{mutationPending ? 'Saving…' : 'Save email'}</button><label className="field-label" htmlFor="access-role">Role</label><select id="access-role" value={accessRole} onChange={(event) => setAccessRole(event.target.value as Account['role'])}><option value="employee">Employee</option><option value="team_administrator">Team administrator</option><option value="system_administrator">System administrator</option></select><button className="button button-secondary" type="button" disabled={mutationPending} onClick={() => setConfirmation({ title: 'Confirm role change', action: 'Apply role change', run: applyRole })}>Apply role</button><label className="field-label" htmlFor="access-team">Team</label><select id="access-team" value={accessTeam} onChange={(event) => setAccessTeam(event.target.value)}>{teams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}</select><div className="row-actions"><button className="button button-secondary" type="button" disabled={mutationPending} onClick={() => void addMembership()}>Add membership</button><button className="button button-secondary" type="button" disabled={mutationPending || !accessTarget.team_ids?.includes(accessTeam)} onClick={() => setConfirmation({ title: 'Remove membership', action: 'Confirm removal', run: removeMembership })}>Remove membership</button></div></div><div className="dialog-actions"><button className="button button-danger" type="button" disabled={accessTarget.status === 'disabled' || mutationPending} onClick={() => setConfirmation({ title: 'Disable account', action: 'Disable account', run: disableAccount })}>Disable account</button><button className="button button-secondary" type="button" onClick={() => setAccessTarget(null)}>Close</button></div></ModalDialog>}
    {keyService && <ModalDialog ariaLabelledBy="keys-title" className="dialog-wide" onDismiss={() => setKeyService(null)}><div className="dialog-heading"><div><p className="section-kicker">{keyService.name}</p><h2 id="keys-title">Group keys</h2></div></div><div className="table-wrap compact-table" tabIndex={0}><table aria-label={`Group keys for ${keyService.name}`}><thead><tr><th>Name</th><th>Prefix</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{keys.length ? keys.map((key) => <tr key={key.id}><td>{key.name}</td><td>{key.prefix}</td><td>{key.status}</td><td><div className="row-actions"><button className="button button-secondary button-small" type="button" disabled={key.status !== 'active'} onClick={() => { setRotateKey(key); setRotateName(`${key.name}-rotated`) }}>Rotate</button><button className="button button-secondary button-small" type="button" disabled={key.status !== 'active'} onClick={() => setRevokeKey(key)}>Revoke</button></div></td></tr>) : <tr><td colSpan={4} className="empty-row">No group keys yet.</td></tr>}</tbody></table></div>{keyPagination.has_more && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={keyPageLoading} onClick={() => void loadMoreKeys()}>{keyPageLoading ? 'Loading…' : 'Load more group keys'}</button></div>}<div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setKeyService(null)}>Close</button><button className="button button-primary" type="button" onClick={() => setKeyCreateOpen(true)}>Create group key</button></div></ModalDialog>}
    {keyCreateOpen && <ModalDialog ariaLabelledBy="group-key-title" onDismiss={() => setKeyCreateOpen(false)} raised><div className="dialog-heading"><h2 id="group-key-title">Create group key</h2></div><form className="dialog-form" onSubmit={createGroupKey}><label className="field-label" htmlFor="group-key-name">Group key name</label><input id="group-key-name" name="group_key_name" aria-label="Group key name" autoComplete="off" spellCheck={false} value={keyName} onChange={(event) => setKeyName(event.target.value)} required /><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setKeyCreateOpen(false)}>Cancel</button><button className="button button-primary" type="submit" disabled={mutationPending}>{mutationPending ? 'Creating…' : 'Create key'}</button></div></form></ModalDialog>}
    {rotateKey && <ModalDialog ariaLabelledBy="rotate-title" onDismiss={() => setRotateKey(null)} raised><div className="dialog-heading"><h2 id="rotate-title">Rotate group key</h2></div><form className="dialog-form" onSubmit={confirmRotateKey}><label className="field-label" htmlFor="rotate-name">New key name</label><input id="rotate-name" name="rotated_key_name" autoComplete="off" spellCheck={false} value={rotateName} onChange={(event) => setRotateName(event.target.value)} required /><p className="credential-warning">The current key will stop working immediately.</p><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setRotateKey(null)}>Cancel</button><button className="button button-danger" type="submit" disabled={mutationPending}>{mutationPending ? 'Rotating…' : 'Confirm rotation'}</button></div></form></ModalDialog>}
    {revokeKey && <ConfirmationDialog title="Revoke group key" action="Confirm revoke" onCancel={() => setRevokeKey(null)} onConfirm={() => void confirmRevokeKey()} raised />}
    {credential && <ModalDialog ariaLabelledBy="credential-title" raised><div className="dialog-heading"><div><p className="section-kicker">One-time display</p><h2 id="credential-title">{credential.title}</h2></div></div><p className="credential-warning">Save this value now. It will not be shown again.</p><code className="credential-value">{credential.value}</code><div className="dialog-actions"><button className="button button-primary" type="button" onClick={() => setCredential(null)}>I have saved this value</button></div></ModalDialog>}
    {reauthOpen && <ModalDialog ariaLabelledBy="reauth-title" onDismiss={() => setReauthOpen(false)} raised><div className="dialog-heading"><h2 id="reauth-title">Reauthenticate</h2></div><form className="dialog-form" onSubmit={finishReauth}><label className="field-label" htmlFor="reauth-password">Current password</label><input id="reauth-password" name="current_password" aria-label="Current password" type="password" autoComplete="current-password" value={reauthPassword} onChange={(event) => setReauthPassword(event.target.value)} required /><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setReauthOpen(false)}>Cancel</button><button className="button button-primary" type="submit" disabled={mutationPending}>{mutationPending ? 'Reauthenticating…' : 'Reauthenticate and continue'}</button></div></form></ModalDialog>}
    {confirmation && <ConfirmationDialog title={confirmation.title} action={confirmation.action} onCancel={() => setConfirmation(null)} onConfirm={() => void confirmation.run().catch(() => setError('Unable to apply this access change.'))} raised />}
  </>
}

function appendUnique<T extends { id: string }>(current: T[], next: T[]): T[] {
	const existing = new Set(current.map((item) => item.id))
	return [...current, ...next.filter((item) => !existing.has(item.id))]
}

async function listAllTeams(client: AdminPortalClient): Promise<Team[]> {
	const teams = await collectAllPages((cursor) => client.listTeams({ status: 'active', ...(cursor ? { cursor } : {}) }))
	return appendUnique([], teams)
}

async function listAllEmployees(client: AdminPortalClient): Promise<Account[]> {
	const accounts = await collectAllPages((cursor) => client.listAccounts({ status: 'active', role: 'employee', ...(cursor ? { cursor } : {}) }))
	return appendUnique([], accounts)
}

function validPricing(model: Model): boolean {
  const input = model.input_unit_price?.trim() ?? ''
  const output = model.output_unit_price?.trim() ?? ''
  const version = model.price_version?.trim() ?? ''
  if (!input && !output && !version) return true
  if (!input || !output || !version) return false
  const decimal = /^(?:0|[1-9]\d*)(?:\.\d+)?$/
  return decimal.test(input) && decimal.test(output) && Number.isFinite(Number(input)) && Number.isFinite(Number(output))
}

function ConfirmationDialog({ title, action, onCancel, onConfirm, raised = false }: { title: string; action: string; onCancel: () => void; onConfirm: () => void; raised?: boolean }) {
  return <ModalDialog ariaLabelledBy="confirmation-title" onDismiss={onCancel} raised={raised}><div className="dialog-heading"><h2 id="confirmation-title">{title}</h2></div><p className="credential-warning">This change is audited and cannot be undone from this screen.</p><div className="dialog-actions"><button className="button button-secondary" type="button" onClick={onCancel}>Cancel</button><button className="button button-danger" type="button" onClick={onConfirm}>{action}</button></div></ModalDialog>
}

function errorCode(reason: unknown): string {
  if (reason instanceof AdminAPIError) return reason.code
  if (reason && typeof reason === 'object' && 'code' in reason && typeof reason.code === 'string') return reason.code
  return ''
}
