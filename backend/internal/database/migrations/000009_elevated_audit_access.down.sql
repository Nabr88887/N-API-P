ALTER TABLE security_events
    DROP COLUMN IF EXISTS query_metadata,
    DROP COLUMN IF EXISTS result_count,
    DROP COLUMN IF EXISTS grant_id,
    DROP COLUMN IF EXISTS session_id;

DROP INDEX IF EXISTS elevated_audit_grants_lookup_idx;
DROP INDEX IF EXISTS elevated_audit_grants_active_session_idx;
DROP TABLE IF EXISTS elevated_audit_grants;
