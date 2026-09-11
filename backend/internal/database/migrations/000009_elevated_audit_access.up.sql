CREATE TABLE elevated_audit_grants (
    id uuid PRIMARY KEY,
    actor_identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    session_id uuid NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    purpose text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT elevated_audit_grants_purpose_valid CHECK (purpose = btrim(purpose) AND length(purpose) BETWEEN 1 AND 500),
    CONSTRAINT elevated_audit_grants_expiry_valid CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '24 hours'),
    CONSTRAINT elevated_audit_grants_revocation_valid CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE INDEX elevated_audit_grants_lookup_idx
    ON elevated_audit_grants (actor_identity_id, session_id, expires_at)
    WHERE revoked_at IS NULL;

ALTER TABLE security_events
    ADD COLUMN session_id uuid REFERENCES sessions (id) ON DELETE RESTRICT,
    ADD COLUMN grant_id uuid REFERENCES elevated_audit_grants (id) ON DELETE RESTRICT,
    ADD COLUMN query_metadata jsonb,
    ADD COLUMN result_count bigint CHECK (result_count IS NULL OR result_count >= 0);

CREATE UNIQUE INDEX elevated_audit_grants_active_session_idx
    ON elevated_audit_grants (actor_identity_id, session_id)
    WHERE revoked_at IS NULL;
