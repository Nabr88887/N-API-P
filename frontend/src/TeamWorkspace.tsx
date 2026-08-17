import { useEffect, useState } from 'react'

import type { UsageRecord } from './employee-api'
import type { TeamMember, TeamPortalClient, TeamUsageAggregate } from './team-api'

type TeamWorkspaceProps = {
  section: string
  teamID: string
  client: TeamPortalClient
}

const emptyAggregate: TeamUsageAggregate = {
  request_count: 0,
  reported_usage_count: 0,
  input_tokens: 0,
  output_tokens: 0,
  total_tokens: 0,
}

export function TeamWorkspace({ section, teamID, client }: TeamWorkspaceProps) {
  const [members, setMembers] = useState<TeamMember[]>([])
  const [usage, setUsage] = useState<UsageRecord[]>([])
  const [aggregate, setAggregate] = useState<TeamUsageAggregate>(emptyAggregate)
  const [memberCursor, setMemberCursor] = useState<string | undefined>()
  const [usageCursor, setUsageCursor] = useState<string | undefined>()
  const [selectedAccountID, setSelectedAccountID] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    if (!teamID) {
      return () => { cancelled = true }
    }
    const load = section === 'Team members'
      ? client.listTeamMembers(teamID).then((response) => {
        if (!cancelled) {
          setError('')
          setMembers(response.data)
          setMemberCursor(response.pagination.next_cursor)
        }
      })
      : Promise.all([
        client.listTeamMembers(teamID),
        selectedAccountID ? client.listTeamUsage(teamID, undefined, selectedAccountID) : client.listTeamUsage(teamID),
      ]).then(([memberResponse, usageResponse]) => {
        if (!cancelled) {
          setError('')
          setMembers(memberResponse.data)
          setUsage(usageResponse.data)
          setAggregate(usageResponse.aggregate)
          setUsageCursor(usageResponse.pagination.next_cursor)
        }
      })
    load.catch(() => {
      if (!cancelled) setError('Unable to load this team workspace right now.')
    }).finally(() => {
      if (!cancelled) setLoading(false)
    })
    return () => { cancelled = true }
  }, [client, section, selectedAccountID, teamID])

  async function loadMoreMembers() {
    if (!memberCursor) return
    const response = await client.listTeamMembers(teamID, memberCursor)
    setMembers((current) => [...current, ...response.data])
    setMemberCursor(response.pagination.next_cursor)
  }

  async function loadMoreUsage() {
    if (!usageCursor) return
    const response = selectedAccountID
      ? await client.listTeamUsage(teamID, usageCursor, selectedAccountID)
      : await client.listTeamUsage(teamID, usageCursor)
    setUsage((current) => [...current, ...response.data])
    setAggregate(response.aggregate)
    setUsageCursor(response.pagination.next_cursor)
  }

  function usageOwnerLabel(record: UsageRecord): string {
    if (record.owner_account_id) {
      return members.find((member) => member.account_id === record.owner_account_id)?.email ?? record.owner_account_id
    }
    return record.service_account_id ?? 'Unknown'
  }

  if (!teamID) return <p className="error-state" role="alert">No assigned team is available for this session.</p>
  if (loading) return <p className="loading-state">Loading team data…</p>
  if (error) return <p className="error-state" role="alert">{error}</p>

  if (section === 'Team members') {
    return (
      <section className="activity-section team-workspace" aria-labelledby="team-members-title">
        <div className="section-heading-row">
          <div><p className="section-kicker">Read-only directory</p><h2 id="team-members-title">Team members</h2></div>
        </div>
        <div className="table-wrap" tabIndex={0}>
          <table aria-label="Team members">
            <thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Joined</th></tr></thead>
            <tbody>{members.length ? members.map((member) => (
              <tr key={member.account_id}><td>{member.email}</td><td>{member.role}</td><td>{member.status}</td><td className="muted-cell">{new Date(member.joined_at).toLocaleDateString()}</td></tr>
            )) : <tr><td className="empty-row" colSpan={4}>No team members found.</td></tr>}</tbody>
          </table>
        </div>
        {memberCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" onClick={loadMoreMembers}>Load more members</button></div>}
      </section>
    )
  }

  return (
    <section className="activity-section team-workspace" aria-labelledby="team-usage-title">
      <div className="section-heading-row">
        <div><p className="section-kicker">Content-free record</p><h2 id="team-usage-title">Team usage</h2></div>
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
      {usageCursor && <div className="pagination-actions"><button className="button button-secondary" type="button" onClick={loadMoreUsage}>Load more usage</button></div>}
    </section>
  )
}
