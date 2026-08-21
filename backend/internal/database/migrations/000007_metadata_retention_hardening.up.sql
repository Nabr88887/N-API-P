DROP TRIGGER security_events_append_only ON security_events;

UPDATE security_events
SET retain_until = occurred_at + INTERVAL '30 days'
WHERE event_type = 'operational_fault'
  AND retain_until IS DISTINCT FROM occurred_at + INTERVAL '30 days';

ALTER TABLE model_allowlist
    ALTER COLUMN updated_by_identity_id DROP NOT NULL;

CREATE OR REPLACE FUNCTION reject_security_event_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.retain_until <= CURRENT_TIMESTAMP THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'security events are append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER security_events_append_only
BEFORE UPDATE OR DELETE ON security_events
FOR EACH ROW EXECUTE FUNCTION reject_security_event_mutation();

CREATE FUNCTION n_api_p_purge_security_events(
    purge_before timestamptz,
    event_class text,
    batch_limit integer
) RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    purged_rows bigint;
BEGIN
    IF purge_before IS NULL
        OR event_class NOT IN ('operational', 'security')
        OR batch_limit < 1
        OR batch_limit > 1000 THEN
        RAISE EXCEPTION 'invalid security-event purge request' USING ERRCODE = '22023';
    END IF;

    WITH candidates AS (
        SELECT id
        FROM security_events
        WHERE retain_until <= purge_before
          AND (
              (event_class = 'operational' AND event_type = 'operational_fault')
              OR (event_class = 'security' AND event_type <> 'operational_fault')
          )
        ORDER BY retain_until, id
        FOR UPDATE SKIP LOCKED
        LIMIT batch_limit
    )
    DELETE FROM security_events AS events
    USING candidates
    WHERE events.id = candidates.id;

    GET DIAGNOSTICS purged_rows = ROW_COUNT;
    RETURN purged_rows;
END;
$$;

CREATE INDEX sessions_identity_retention_idx ON sessions (identity_id, id);
CREATE INDEX one_time_codes_identity_retention_idx ON one_time_codes (identity_id, id);
CREATE INDEX one_time_codes_issuer_retention_idx ON one_time_codes (issued_by_identity_id, id);
CREATE INDEX model_allowlist_updater_retention_idx ON model_allowlist (updated_by_identity_id, model_id)
    WHERE updated_by_identity_id IS NOT NULL;
CREATE INDEX audit_records_key_retention_idx ON audit_records (key_id, id);
CREATE INDEX audit_records_service_retention_idx ON audit_records (service_account_id, id)
    WHERE service_account_id IS NOT NULL;
CREATE INDEX audit_records_responsible_retention_idx ON audit_records (responsible_identity_id, id)
    WHERE responsible_identity_id IS NOT NULL;
CREATE INDEX usage_records_key_retention_idx ON usage_records (key_id, id);
CREATE INDEX usage_records_service_retention_idx ON usage_records (service_account_id, id)
    WHERE service_account_id IS NOT NULL;
CREATE INDEX usage_records_responsible_retention_idx ON usage_records (responsible_identity_id, id)
    WHERE responsible_identity_id IS NOT NULL;
CREATE INDEX security_events_target_identity_retention_idx ON security_events (target_identity_id, id)
    WHERE target_identity_id IS NOT NULL;
CREATE INDEX security_events_target_service_retention_idx ON security_events (target_service_account_id, id)
    WHERE target_service_account_id IS NOT NULL;
CREATE INDEX security_events_target_key_retention_idx ON security_events (target_key_id, id)
    WHERE target_key_id IS NOT NULL;
