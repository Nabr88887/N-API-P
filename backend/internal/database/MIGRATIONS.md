# Migration Policy

## 000002 Workforce Access

Migration `000002_workforce_access` is additive: it creates new first-release
tables. The preceding scaffold does not connect to PostgreSQL at startup, so it
has no database column contract that this migration can break.

There is intentionally no destructive down migration. Before production data
exists, disposable test environments are reset by dropping only their dedicated
test schema. After data exists, rollback means stopping ingress and restoring
the prior compatible image. A schema defect is repaired by a new forward
migration; if compatibility cannot be preserved, restoration requires the
separately confirmed backup or equivalent recovery point. Production operators
must not use `DROP TABLE` or decrement migration state for this migration.

## 000003 Audit, Policy, and Operations

Migration `000003_audit_policy_operations` is additive and keeps encrypted raw
content in a table separate from backed-up metadata. It defaults the durable
audit gate to `blocked` so a restarted application must prove persistence
health before chat dispatch. Security events reject ordinary updates and
deletes; a later retention-maintenance task must add and test a narrowly scoped
purge path before any event reaches its two-year boundary.

The frozen version-2 workforce consumer remains able to perform its explicit,
parameterized read and update operations after this migration.

There is no destructive down migration. Before production data exists, reset
only the dedicated disposable test schema. After data exists, roll back to the
prior compatible image or repair with a new forward migration. If a repair
cannot preserve compatibility, use the separately confirmed metadata recovery
point; raw-content rows remain excluded from that backup boundary.

## 000004 Repository Indexes

Migration `000004_repository_indexes` adds only secondary indexes for bounded
ownership, status, chronological, expiration, retention, and audit-correlation
queries. It does not change table or column contracts, so prior schema consumers
remain compatible with the indexed schema.

The frozen version-2 workforce and version-3 audit/usage consumers remain able
to perform their explicit, parameterized read and update operations after this
migration.

There is no destructive down migration. Before production data exists, reset
only the dedicated disposable test schema. After data exists, roll back the
application image without removing the indexes; repair an invalid or incomplete
index definition with a new forward migration. Production index rollout and
lock behavior remain behind the separate non-test migration and deployment
approval gates.

## Compatibility Evidence

Task 2.5 migrates one isolated synthetic schema through versions 2 through 7.
It seeds data through frozen version-2 workforce SQL, reruns that same consumer
after every later version, seeds version-3 audit/usage/security data, and reruns
the same version-3 consumer after every later version. The probes enumerate selected columns,
parameterize every value, exercise both reads and writes, and verify retained
ownership and audit correlations. A schema-compatible application rollback does
not require a schema downgrade.

This is schema/consumer compatibility evidence, not a real container-image
rollback drill: no earlier versioned application image exists yet, and the
current scaffold has no runtime database connection. A real prior-image start,
metadata backup/restore, credential invalidation, and recovery-time drill remain
deployment-stage acceptance work under their own approval gates. Until that
artifact exists, reports must not describe the contract probes as an image or
backup-restore rehearsal.

## 000005 Lifecycle Maintenance

Migration `000005_lifecycle_maintenance` makes `api_keys.verification_hash`
nullable only when the key is already revoked. Active keys still require a
non-empty hash, while revoked key ID, prefix, ownership, status, and timestamps
remain available after lifecycle cleanup removes verification material.

The migration is forward compatible with frozen version-2 workforce and
version-3 audit consumers: existing inserts remain valid, active-key reads keep
their non-null contract, and neither consumer selects revoked verification
hashes. There is no destructive down migration because purged hashes cannot be
reconstructed. Disposable test schemas are reset as a unit; deployed rollback
uses a prior compatible application image or a new forward repair migration.

## 000006 Metadata Retention

Migration `000006_metadata_retention` adds lookup indexes for metadata expiry
and the original maintenance path for deleting expired append-only events. Its
GUC-based trigger exception is superseded by migration 000007 and must not be
used as a release authorization boundary.

## 000007 Metadata Retention Hardening

Migration `000007_metadata_retention_hardening` backfills historical
`operational_fault` events to the 30-day retention class, makes model-policy
updater ownership nullable so the policy survives ownership expiry, adds the
foreign-key lookup indexes used by bounded cleanup, and installs the bounded
`n_api_p_purge_security_events` function. The append-only trigger ignores the
legacy maintenance GUC and permits deletion only after `retain_until`; retained
events still reject updates and deletes.

The down migration removes the new function and indexes and restores the
version-6 trigger behavior. It intentionally leaves
`model_allowlist.updated_by_identity_id` nullable because a removed historical
updater cannot be reconstructed safely. Deployed rollback uses a compatible
prior image or a new forward repair rather than a destructive schema downgrade.

## 000008 Governed Investigations

Migration `000008_governed_investigations` adds metadata-only investigation
cases, immutable candidate membership, session-bound access grants, and
nullable case attribution on security events. Candidate membership cascades
when its case is deleted, but deliberately has no foreign key to `audit_records`:
the candidate UUID snapshot remains after audit metadata is purged, so case rows
never prevent independent raw-content expiry or metadata cleanup. The down
migration is for disposable schemas only; deployed rollback disables the routes
and uses a forward repair or a separately confirmed recovery point.

## 000009 Elevated Audit Access

Migration `000009_elevated_audit_access` adds session-bound, revocable elevated
audit grants and the grant/query metadata columns used by content-free security
events. The grant table is metadata-only and does not contain raw request or
response content. The down migration is for disposable schemas only; deployed
rollback disables the routes and uses a forward repair or a separately
confirmed recovery point.
