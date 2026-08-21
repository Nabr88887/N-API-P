DROP INDEX IF EXISTS security_events_target_key_retention_idx;
DROP INDEX IF EXISTS security_events_target_service_retention_idx;
DROP INDEX IF EXISTS security_events_target_identity_retention_idx;
DROP INDEX IF EXISTS usage_records_responsible_retention_idx;
DROP INDEX IF EXISTS usage_records_service_retention_idx;
DROP INDEX IF EXISTS usage_records_key_retention_idx;
DROP INDEX IF EXISTS audit_records_responsible_retention_idx;
DROP INDEX IF EXISTS audit_records_service_retention_idx;
DROP INDEX IF EXISTS audit_records_key_retention_idx;
DROP INDEX IF EXISTS model_allowlist_updater_retention_idx;
DROP INDEX IF EXISTS one_time_codes_issuer_retention_idx;
DROP INDEX IF EXISTS one_time_codes_identity_retention_idx;
DROP INDEX IF EXISTS sessions_identity_retention_idx;

DROP FUNCTION IF EXISTS n_api_p_purge_security_events(timestamptz, text, integer);

DROP TRIGGER security_events_append_only ON security_events;

CREATE OR REPLACE FUNCTION reject_security_event_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('n_api_p.retention_maintenance', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'security events are append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER security_events_append_only
BEFORE UPDATE OR DELETE ON security_events
FOR EACH ROW EXECUTE FUNCTION reject_security_event_mutation();
