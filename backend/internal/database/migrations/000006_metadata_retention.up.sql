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

CREATE INDEX security_events_retention_event_type_idx ON security_events (retain_until, event_type);
CREATE INDEX identities_disabled_retention_idx ON identities (disabled_at) WHERE status = 'disabled';
CREATE INDEX service_accounts_disabled_retention_idx ON service_accounts (disabled_at) WHERE status = 'disabled';
CREATE INDEX api_keys_revoked_retention_idx ON api_keys (revoked_at) WHERE status = 'revoked';
