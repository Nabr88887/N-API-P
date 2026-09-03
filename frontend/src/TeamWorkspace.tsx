import { useEffect, useRef, useState } from 'react'

import type { UsageRecord } from './employee-api'
import type { TeamMember, TeamPortalClient, TeamUsageAggregate } from './team-api'
import { advanceCursor, collectAllPages } from './pagination'

type TeamWorkspaceProps = {
  section: string
  teamID: string
  teamIDs?: string[]
  client: TeamPortalClient
}

const emptyAggregate: TeamUsageAggregate = {
  request_count: 0,
  reported_usage_count: 0,
  input_tokens: 0,
  output_tokens: 0,
  total_tokens: 0,
}

export function TeamWorkspace({ section, teamID, teamIDs = [], client }: TeamWorkspaceProps) {
  const availableTeamIDs = Array.from(new Set(teamIDs.length ? teamIDs : teamID ? [teamID] : []))
  const [selectedTeamID, setSelectedTeamID] = useState(teamID || availableTeamIDs[0] || '')
  const [members, setMembers] = useState<TeamMember[]>([])
  const [usage, setUsage] = useState<UsageRecord[]>([])
  const [aggregate, setAggregate] = useState<TeamUsageAggregate>(emptyAggregate)
  const [memberCursor, setMemberCursor] = useState<string | undefined>()
  const [usageCursor, setUsageCursor] = useState<string | undefined>()
  const [selectedAccountID, setSelectedAccountID] = useState('')
  const loadKey = JSON.stringify([section, selectedTeamID, selectedAccountID])
  const [loadedKey, setLoadedKey] = useState('')
  const [error, setError] = useState('')
  const [paginationError, setPaginationError] = useState('')
  const [membersLoading, setMembersLoading] = useState(false)
  const [usageLoading, setUsageLoading] = useState(false)
  const memberCursors = useRef(new Set<string>())
  const usageCursors = useRef(new Set<string>())

  function switchTeam(nextTeamID: string) {
    setSelectedAccountID('')
    setError('')
    setPaginationError('')
    setMembers([])
    setUsage([])
    setAggregate(emptyAggregate)
    setMemberCursor(undefined)
    setUsageCursor(undefined)
    setSelectedTeamID(nextTeamID)
  }

  useEffect(() => {
    let cancelled = false
    if (!selectedTeamID) {
      return () => { cancelled = true }
    }
    const cursors = new Set<string>()
    if (section === 'Team members') memberCursors.current = cursors
    else usageCursors.current = cursors
    const load = section === 'Team members'
      ? client.listTeamMembers(selectedTeamID).then((response) => {
        if (!cancelled) {
          setMembers(response.data)
          setMemberCursor(advanceCursor(response.pagination, cursors))
        }
      })
      : Promise.all([loadAllMembers(client, selectedTeamID), selectedAccountID ? client.listTeamUsage(selectedTeamID, undefined, selectedAccountID) : client.listTeamUsage(selectedTeamID)]).then(([memberResponse, usageResponse]) => {
        if (!cancelled) {
          setMembers(memberResponse)
          setUsage(usageResponse.data)
          setAggregate(usageResponse.aggregate)
          setUsageCursor(advanceCursor(usageResponse.pagination, cursors))
        }
      })
    load.then(() => {
      if (!cancelled) {
        setError('')
        setPaginationError('')
      }
    }).catch(() => {
      if (!cancelled) setError('Unable to load this team workspace right now.')
    }).finally(() => {
      if (!cancelled) setLoadedKey(loadKey)
    })
    return () => { cancelled = true }
  }, [client, loadKey, section, selectedAccountID, selectedTeamID])

  async function loadMoreMembers() {
    if (!memberCursor || membersLoading || !selectedTeamID) return
    setMembersLoading(true)
    setPaginationError('')
    try {
      const response = await client.listTeamMembers(selectedTeamID, memberCursor)
      const nextCursor = advanceCursor(response.pagination, memberCursors.current)
      setMembers((current) => [...current, ...response.data.filter((item) => !current.some((existing) => existing.account_id === item.account_id))])
      setMemberCursor(nextCursor)
    } catch (failure: unknown) {
      if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setMemberCursor(undefined)
      setPaginationError('Unable to load more members.')
    } finally {
      setMembersLoading(false)
    }
  }

  async function loadMoreUsage() {
    if (!usageCursor || usageLoading || !selectedTeamID) return
    setUsageLoading(true)
    setPaginationError('')
    try {
      const response = selectedAccountID
        ? await client.listTeamUsage(selectedTeamID, usageCursor, selectedAccountID)
        : await client.listTeamUsage(selectedTeamID, usageCursor)
      const nextCursor = advanceCursor(response.pagination, usageCursors.current)
      setUsage((current) => [...current, ...response.data.filter((item) => !current.some((existing) => existing.id === item.id))])
      setAggregate(response.aggregate)
      setUsageCursor(nextCursor)
    } catch (failure: unknown) {
      if (failure instanceof Error && failure.message === 'INVALID_PAGINATION_CURSOR') setUsageCursor(undefined)
      setPaginationError('Unable to load more usage records.')
    } finally {
      setUsageLoading(false)
    }
  }

  function usageOwnerLabel(record: UsageRecord): string {
    if (record.owner_account_id) {
      return members.find((member) => member.account_id === record.owner_account_id)?.email ?? record.owner_account_id
    }
    return record.service_account_id ?? 'Unknown'
  }

  if (!selectedTeamID) return <p className="error-state" role="alert">No assigned team is available for this session.</p>
  if (loadedKey !== loadKey) return <p className="loading-state">Loading team data…</p>
  if (error) return <p className="error-state" role="alert">{error}</p>

  if (section === 'Team members') {
    return (
      <section className="activity-section team-workspace" aria-labelledby="team-members-title">
        <div className="section-heading-row">
          <div><p className="section-kicker">Read-only directory</p><h2 id="team-members-title">Team members</h2></div>
          {availableTeamIDs.length > 1 && <TeamSelector teamIDs={availableTeamIDs} value={selectedTeamID} onChange={switchTeam} />}
        </div>
        <div className="table-wrap" tabIndex={0}>
          <table aria-label="Team members">
            <thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Joined</th></tr></thead>
            <tbody>{members.length ? members.map((member) => (
              <tr key={member.account_id}><td>{member.email}</td><td>{member.role}</td><td>{member.status}</td><td className="muted-cell">{new Date(member.joined_at).toLocaleDateString()}</td></tr>
            )) : <tr><td className="empty-row" colSpan={4}>No team members found.</td></tr>}</tbody>
          </table>
        </div>
        {paginationError && <p className="error-state" role="alert">{paginationError}</p>}
        {memberCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={membersLoading} onClick={() => void loadMoreMembers()}>{membersLoading ? 'Loading…' : 'Load more members'}</button></div>}
      </section>
    )
  }

  return (
    <section className="activity-section team-workspace" aria-labelledby="team-usage-title">
      <div className="section-heading-row">
        <div><p className="section-kicker">Content-free record</p><h2 id="team-usage-title">Team usage</h2></div>
        {availableTeamIDs.length > 1 && <TeamSelector teamIDs={availableTeamIDs} value={selectedTeamID} onChange={switchTeam} />}
        <div className="scope-filter"><label className="field-label" htmlFor="usage-scope">Usage scope</label><select id="usage-scope" aria-label="Usage scope" value={selectedAccountID} onChange={(event) => setSelectedAccountID(event.target.value)}><option value="">All team members and services</option>{members.map((member) => <option key={member.account_id} value={member.account_id}>{member.email}</option>)}</select></div>
      </div>
      <section className="team-usage-summary metric-grid" aria-label="Team usage summary">
        <article className="metric-card"><p>Requests</p><strong>{aggregate.request_count.toLocaleString()}</strong><span>{selectedAccountID ? 'Selected member records' : 'All team usage records'}</span></article>
        <article className="metric-card metric-card-blue"><p>Total tokens</p><strong>{aggregate.total_tokens.toLocaleString()}</strong><span>{aggregate.reported_usage_count.toLocaleString()} records reported usage</span></article>
        <article className="metric-card metric-card-amber"><p>Input / output</p><strong>{aggregate.input_tokens.toLocaleString()}</strong><span>{aggregate.output_tokens.toLocaleString()} output tokens</span></article>
      </section>
      <div className="table-wrap" tabIndex={0}>
        <table aria-label="Team usage records">
          <thead><tr><th scope="col">When</th><th scope="col">Owner</th><th scope="col">Model</th><th scope="col">Outcome</th><th scope="col">Tokens</th></tr></thead>
          <tbody>{usage.length ? usage.map((record) => (
            <tr key={record.id}><td className="muted-cell">{new Date(record.created_at).toLocaleString()}</td><td>{usageOwnerLabel(record)}</td><td>{record.model_id}</td><td>{record.outcome}</td><td>{record.usage?.total_tokens ?? 'Unknown'}</td></tr>
          )) : <tr><td className="empty-row" colSpan={5}>No team usage records yet.</td></tr>}</tbody>
        </table>
      </div>
      {paginationError && <p className="error-state" role="alert">{paginationError}</p>}
      {usageCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" disabled={usageLoading} onClick={() => void loadMoreUsage()}>{usageLoading ? 'Loading…' : 'Load more usage'}</button></div>}
    </section>
  )
}

function TeamSelector({ teamIDs, value, onChange }: { teamIDs: string[]; value: string; onChange: (teamID: string) => void }) {
  return <label className="field-label" htmlFor="team-scope">Team scope<select id="team-scope" aria-label="Team scope" value={value} onChange={(event) => onChange(event.target.value)}>{teamIDs.map((id) => <option key={id} value={id}>{id}</option>)}</select></label>
}

async function loadAllMembers(client: TeamPortalClient, teamID: string): Promise<TeamMember[]> {
  const members = await collectAllPages((cursor) => client.listTeamMembers(teamID, cursor))
  return members.filter((item, index) => members.findIndex((candidate) => candidate.account_id === item.account_id) === index)
}
