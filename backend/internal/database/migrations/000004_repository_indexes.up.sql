CREATE INDEX identities_status_created_idx
    ON identities (status, created_at DESC, id DESC);

CREATE INDEX teams_status_created_idx
    ON teams (status, created_at DESC, id DESC);

CREATE INDEX memberships_team_identity_idx
    ON memberships (team_id, identity_id);

CREATE INDEX service_accounts_team_status_idx
    ON service_accounts (team_id, status, created_at DESC, id DESC);

CREATE INDEX service_accounts_responsible_status_idx
    ON service_accounts (responsible_identity_id, status, created_at DESC, id DESC);

CREATE INDEX sessions_identity_active_idx
    ON sessions (identity_id, idle_expires_at, absolute_expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX sessions_idle_expiry_idx
    ON sessions (idle_expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX sessions_absolute_expiry_idx
    ON sessions (absolute_expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX one_time_codes_identity_purpose_expiry_idx
    ON one_time_codes (identity_id, purpose, expires_at DESC)
    WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE INDEX one_time_codes_expiry_idx
    ON one_time_codes (expires_at)
    WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE INDEX api_keys_identity_status_created_idx
    ON api_keys (identity_id, status, created_at DESC, id DESC)
    WHERE identity_id IS NOT NULL;

CREATE INDEX api_keys_service_status_created_idx
    ON api_keys (service_account_id, status, created_at DESC, id DESC)
    WHERE service_account_id IS NOT NULL;

CREATE INDEX api_keys_revoked_idx
    ON api_keys (revoked_at, id)
    WHERE revoked_at IS NOT NULL;

CREATE INDEX model_allowlist_status_model_idx
    ON model_allowlist (status, model_id);

CREATE INDEX audit_records_created_idx
    ON audit_records (created_at DESC, id DESC);

CREATE INDEX audit_records_identity_created_idx
    ON audit_records (identity_id, created_at DESC, id DESC)
    WHERE identity_id IS NOT NULL;

CREATE INDEX audit_records_team_created_idx
    ON audit_records (team_id, created_at DESC, id DESC);

CREATE INDEX audit_records_capture_status_updated_idx
    ON audit_records (capture_status, updated_at, id);

CREATE INDEX audit_records_upstream_request_idx
    ON audit_records (upstream_request_id)
    WHERE upstream_request_id IS NOT NULL;

CREATE INDEX audit_raw_content_expiry_idx
    ON audit_raw_content (expires_at, audit_id, content_kind);

CREATE INDEX usage_records_identity_created_idx
    ON usage_records (identity_id, created_at DESC, id DESC)
    WHERE identity_id IS NOT NULL;

CREATE INDEX usage_records_team_created_idx
    ON usage_records (team_id, created_at DESC, id DESC);

CREATE INDEX usage_records_created_idx
    ON usage_records (created_at DESC, id DESC);

CREATE INDEX security_events_occurred_idx
    ON security_events (occurred_at DESC, id DESC);

CREATE INDEX security_events_retention_idx
    ON security_events (retain_until, id);

CREATE INDEX security_events_request_idx
    ON security_events (request_id, occurred_at DESC, id DESC);

CREATE INDEX security_events_target_audit_idx
    ON security_events (target_audit_id, occurred_at DESC, id DESC)
    WHERE target_audit_id IS NOT NULL;

CREATE INDEX security_events_actor_occurred_idx
    ON security_events (actor_identity_id, occurred_at DESC, id DESC)
    WHERE actor_identity_id IS NOT NULL;
