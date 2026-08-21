DROP INDEX IF EXISTS api_keys_revoked_retention_idx;
DROP INDEX IF EXISTS service_accounts_disabled_retention_idx;
DROP INDEX IF EXISTS identities_disabled_retention_idx;
DROP INDEX IF EXISTS security_events_retention_event_type_idx;

CREATE OR REPLACE FUNCTION reject_security_event_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'security events are append-only' USING ERRCODE = '55000';
END;
$$;
