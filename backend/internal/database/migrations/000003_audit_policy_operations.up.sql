CREATE TABLE model_allowlist (
    model_id text PRIMARY KEY,
    status text NOT NULL,
    input_unit_price numeric(24, 12),
    output_unit_price numeric(24, 12),
    price_version text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by_identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    CONSTRAINT model_allowlist_model_id_valid CHECK (model_id = btrim(model_id) AND length(model_id) > 0),
    CONSTRAINT model_allowlist_status_valid CHECK (status IN ('allowed', 'disabled')),
    CONSTRAINT model_allowlist_price_snapshot_complete CHECK (
        (input_unit_price IS NULL AND output_unit_price IS NULL AND price_version IS NULL)
        OR (input_unit_price IS NOT NULL AND output_unit_price IS NOT NULL AND price_version IS NOT NULL
            AND input_unit_price >= 0 AND output_unit_price >= 0 AND length(price_version) > 0)
    )
);

CREATE TABLE audit_records (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE,
    key_id uuid NOT NULL REFERENCES api_keys (id) ON DELETE RESTRICT,
    owner_kind text NOT NULL,
    identity_id uuid REFERENCES identities (id) ON DELETE RESTRICT,
    service_account_id uuid REFERENCES service_accounts (id) ON DELETE RESTRICT,
    responsible_identity_id uuid REFERENCES identities (id) ON DELETE RESTRICT,
    team_id uuid NOT NULL REFERENCES teams (id) ON DELETE RESTRICT,
    model_id text NOT NULL,
    capture_status text NOT NULL,
    outcome text NOT NULL,
    upstream_request_id text,
    upstream_http_status integer,
    error_code text,
    finish_reason text,
    observed_request_bytes bigint NOT NULL,
    observed_response_bytes bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamptz,
    UNIQUE (id, request_id),
    CONSTRAINT audit_records_owner_valid CHECK (
        (owner_kind = 'personal' AND identity_id IS NOT NULL AND service_account_id IS NULL AND responsible_identity_id IS NULL)
        OR (owner_kind = 'service' AND identity_id IS NULL AND service_account_id IS NOT NULL AND responsible_identity_id IS NOT NULL)
    ),
    CONSTRAINT audit_records_model_valid CHECK (model_id = btrim(model_id) AND length(model_id) > 0),
    CONSTRAINT audit_records_capture_status_valid CHECK (capture_status IN ('pending', 'complete', 'truncated', 'incomplete')),
    CONSTRAINT audit_records_outcome_valid CHECK (outcome IN ('pending', 'success', 'upstream_error', 'cancelled', 'local_error')),
    CONSTRAINT audit_records_http_status_valid CHECK (upstream_http_status IS NULL OR upstream_http_status BETWEEN 100 AND 599),
    CONSTRAINT audit_records_sizes_valid CHECK (observed_request_bytes >= 0 AND observed_response_bytes >= 0),
    CONSTRAINT audit_records_completion_valid CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE TABLE audit_raw_content (
    audit_id uuid NOT NULL REFERENCES audit_records (id) ON DELETE RESTRICT,
    content_kind text NOT NULL,
    compression text NOT NULL,
    ciphertext bytea NOT NULL,
    cipher_nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    wrap_nonce bytea NOT NULL,
    key_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (audit_id, content_kind),
    CONSTRAINT audit_raw_content_kind_valid CHECK (content_kind IN ('request', 'response')),
    CONSTRAINT audit_raw_content_compression_valid CHECK (compression = btrim(compression) AND length(compression) > 0),
    CONSTRAINT audit_raw_content_ciphertext_valid CHECK (octet_length(ciphertext) > 16),
    CONSTRAINT audit_raw_content_cipher_nonce_valid CHECK (octet_length(cipher_nonce) = 12),
    CONSTRAINT audit_raw_content_wrapped_key_valid CHECK (octet_length(wrapped_data_key) > 16),
    CONSTRAINT audit_raw_content_wrap_nonce_valid CHECK (octet_length(wrap_nonce) = 12),
    CONSTRAINT audit_raw_content_key_version_valid CHECK (key_version > 0),
    CONSTRAINT audit_raw_content_expiry_valid CHECK (expires_at > created_at)
);

CREATE TABLE usage_records (
    id uuid PRIMARY KEY,
    audit_id uuid NOT NULL UNIQUE REFERENCES audit_records (id) ON DELETE RESTRICT,
    request_id uuid NOT NULL UNIQUE,
    key_id uuid NOT NULL REFERENCES api_keys (id) ON DELETE RESTRICT,
    owner_kind text NOT NULL,
    identity_id uuid REFERENCES identities (id) ON DELETE RESTRICT,
    service_account_id uuid REFERENCES service_accounts (id) ON DELETE RESTRICT,
    responsible_identity_id uuid REFERENCES identities (id) ON DELETE RESTRICT,
    team_id uuid NOT NULL REFERENCES teams (id) ON DELETE RESTRICT,
    model_id text NOT NULL,
    upstream_request_id text,
    outcome text NOT NULL,
    usage_reported boolean NOT NULL,
    input_tokens bigint,
    output_tokens bigint,
    total_tokens bigint,
    price_version text,
    input_unit_price numeric(24, 12),
    output_unit_price numeric(24, 12),
    calculated_amount numeric(24, 12),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (audit_id, request_id) REFERENCES audit_records (id, request_id) ON DELETE RESTRICT,
    CONSTRAINT usage_records_owner_valid CHECK (
        (owner_kind = 'personal' AND identity_id IS NOT NULL AND service_account_id IS NULL AND responsible_identity_id IS NULL)
        OR (owner_kind = 'service' AND identity_id IS NULL AND service_account_id IS NOT NULL AND responsible_identity_id IS NOT NULL)
    ),
    CONSTRAINT usage_records_model_valid CHECK (model_id = btrim(model_id) AND length(model_id) > 0),
    CONSTRAINT usage_records_outcome_valid CHECK (outcome IN ('success', 'upstream_error', 'cancelled', 'local_error')),
    CONSTRAINT usage_records_usage_complete CHECK (
        (NOT usage_reported AND input_tokens IS NULL AND output_tokens IS NULL AND total_tokens IS NULL)
        OR (usage_reported AND input_tokens IS NOT NULL AND output_tokens IS NOT NULL AND total_tokens IS NOT NULL
            AND input_tokens >= 0 AND output_tokens >= 0 AND total_tokens >= 0)
    ),
    CONSTRAINT usage_records_token_total_valid CHECK (total_tokens IS NULL OR total_tokens = input_tokens + output_tokens),
    CONSTRAINT usage_records_price_snapshot_complete CHECK (
        (price_version IS NULL AND input_unit_price IS NULL AND output_unit_price IS NULL AND calculated_amount IS NULL)
        OR (price_version IS NOT NULL AND input_unit_price IS NOT NULL AND output_unit_price IS NOT NULL AND calculated_amount IS NOT NULL
            AND length(price_version) > 0 AND input_unit_price >= 0 AND output_unit_price >= 0 AND calculated_amount >= 0)
    )
);

CREATE TABLE security_events (
    id uuid PRIMARY KEY,
    event_type text NOT NULL,
    actor_identity_id uuid REFERENCES identities (id) ON DELETE RESTRICT,
    target_identity_id uuid REFERENCES identities (id) ON DELETE RESTRICT,
    target_service_account_id uuid REFERENCES service_accounts (id) ON DELETE RESTRICT,
    target_key_id uuid REFERENCES api_keys (id) ON DELETE RESTRICT,
    target_audit_id uuid REFERENCES audit_records (id) ON DELETE RESTRICT,
    request_id uuid NOT NULL,
    outcome text NOT NULL,
    reason text,
    detail_code text,
    occurred_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retain_until timestamptz NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '2 years'),
    CONSTRAINT security_events_type_valid CHECK (event_type = btrim(event_type) AND length(event_type) > 0),
    CONSTRAINT security_events_outcome_valid CHECK (outcome IN ('success', 'denied', 'failure')),
    CONSTRAINT security_events_reason_valid CHECK (reason IS NULL OR length(btrim(reason)) > 0),
    CONSTRAINT security_events_retention_valid CHECK (retain_until > occurred_at)
);

CREATE FUNCTION reject_security_event_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'security events are append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER security_events_append_only
BEFORE UPDATE OR DELETE ON security_events
FOR EACH ROW EXECUTE FUNCTION reject_security_event_mutation();

CREATE TABLE operational_state (
    id smallint PRIMARY KEY,
    raw_retention_days smallint NOT NULL,
    audit_gate_state text NOT NULL,
    audit_gate_reason_code text,
    gate_changed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_persistence_probe_at timestamptz,
    last_cleanup_at timestamptz,
    deletion_overdue_since timestamptz,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT operational_state_singleton CHECK (id = 1),
    CONSTRAINT operational_state_retention_valid CHECK (raw_retention_days BETWEEN 1 AND 30),
    CONSTRAINT operational_state_gate_valid CHECK (audit_gate_state IN ('open', 'blocked')),
    CONSTRAINT operational_state_gate_reason_valid CHECK (
        (audit_gate_state = 'open' AND audit_gate_reason_code IS NULL)
        OR (audit_gate_state = 'blocked' AND audit_gate_reason_code IS NOT NULL AND length(audit_gate_reason_code) > 0)
    )
);

INSERT INTO operational_state (id, raw_retention_days, audit_gate_state, audit_gate_reason_code)
VALUES (1, 7, 'blocked', 'startup_probe_required');
