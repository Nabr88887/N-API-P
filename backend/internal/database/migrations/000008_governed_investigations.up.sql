CREATE TABLE investigation_cases (
    id uuid PRIMARY KEY,
    subject_identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    policy_concern text NOT NULL,
    reason text NOT NULL,
    start_at timestamptz NOT NULL,
    end_at timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'open',
    created_by_identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_by_identity_id uuid REFERENCES identities (id) ON DELETE RESTRICT,
    closed_at timestamptz,
    disposition text,
    closure_note text,
    CONSTRAINT investigation_cases_policy_concern_valid CHECK (length(btrim(policy_concern)) > 0 AND length(policy_concern) <= 500),
    CONSTRAINT investigation_cases_reason_valid CHECK (length(btrim(reason)) > 0 AND length(reason) <= 500),
    CONSTRAINT investigation_cases_scope_valid CHECK (start_at < end_at AND end_at <= created_at AND end_at - start_at <= INTERVAL '30 days'),
    CONSTRAINT investigation_cases_status_valid CHECK (status IN ('open', 'closed')),
    CONSTRAINT investigation_cases_lifecycle_valid CHECK (
        (status = 'open' AND closed_by_identity_id IS NULL AND closed_at IS NULL AND disposition IS NULL)
        OR (status = 'closed' AND closed_by_identity_id IS NOT NULL AND closed_at IS NOT NULL AND disposition IN ('confirmed_violation', 'no_violation', 'inconclusive'))
    ),
    CONSTRAINT investigation_cases_closure_time_valid CHECK (closed_at IS NULL OR closed_at >= created_at),
    CONSTRAINT investigation_cases_closure_note_valid CHECK (closure_note IS NULL OR length(closure_note) <= 500)
);

CREATE TABLE investigation_case_audits (
    case_id uuid NOT NULL REFERENCES investigation_cases (id) ON DELETE CASCADE,
    -- The candidate UUID is an immutable snapshot. It is intentionally not a
    -- foreign key so audit metadata can expire independently of the case.
    audit_id uuid NOT NULL,
    ordinal smallint NOT NULL,
    capture_status text NOT NULL,
    audit_created_at timestamptz NOT NULL,
    raw_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (case_id, audit_id),
    UNIQUE (case_id, ordinal),
    CONSTRAINT investigation_case_audits_ordinal_valid CHECK (ordinal BETWEEN 1 AND 100),
    CONSTRAINT investigation_case_audits_status_valid CHECK (capture_status IN ('pending', 'complete', 'truncated', 'incomplete')),
    CONSTRAINT investigation_case_audits_expiry_valid CHECK (raw_expires_at > audit_created_at)
);

CREATE TABLE investigation_access_grants (
    id uuid PRIMARY KEY,
    case_id uuid NOT NULL REFERENCES investigation_cases (id) ON DELETE CASCADE,
    actor_identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    session_id uuid NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT investigation_access_grants_expiry_valid CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '30 minutes'),
    CONSTRAINT investigation_access_grants_revocation_valid CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

ALTER TABLE security_events
    ADD COLUMN investigation_case_id uuid REFERENCES investigation_cases (id) ON DELETE RESTRICT;

ALTER TABLE security_events
    ADD CONSTRAINT security_events_investigation_case_valid
    CHECK (investigation_case_id IS NULL OR event_type LIKE 'investigation\_%' ESCAPE '\');

CREATE INDEX investigation_cases_status_created_idx
    ON investigation_cases (status, created_at DESC, id DESC);

CREATE INDEX investigation_cases_subject_created_idx
    ON investigation_cases (subject_identity_id, created_at DESC, id DESC);

CREATE INDEX investigation_case_audits_audit_idx
    ON investigation_case_audits (audit_id, case_id);

CREATE INDEX investigation_access_grants_lookup_idx
    ON investigation_access_grants (case_id, actor_identity_id, session_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX security_events_investigation_case_idx
    ON security_events (investigation_case_id, occurred_at DESC, id DESC)
    WHERE investigation_case_id IS NOT NULL;
