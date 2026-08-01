CREATE TABLE identities (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE,
    password_hash text,
    role text NOT NULL,
    status text NOT NULL,
    failed_login_attempts integer NOT NULL DEFAULT 0,
    failed_login_window_started_at timestamptz,
    locked_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disabled_at timestamptz,
    CONSTRAINT identities_email_normalized CHECK (email = lower(btrim(email)) AND length(email) > 0),
    CONSTRAINT identities_role_valid CHECK (role IN ('employee', 'team_administrator', 'system_administrator')),
    CONSTRAINT identities_status_valid CHECK (status IN ('pending', 'active', 'disabled')),
    CONSTRAINT identities_failed_login_attempts_valid CHECK (failed_login_attempts >= 0),
    CONSTRAINT identities_disabled_time_valid CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
);

CREATE TABLE teams (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    status text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disabled_at timestamptz,
    CONSTRAINT teams_name_valid CHECK (name = btrim(name) AND length(name) > 0),
    CONSTRAINT teams_status_valid CHECK (status IN ('active', 'disabled')),
    CONSTRAINT teams_disabled_time_valid CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
);

CREATE TABLE memberships (
    identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    team_id uuid NOT NULL REFERENCES teams (id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (identity_id, team_id)
);

CREATE TABLE service_accounts (
    id uuid PRIMARY KEY,
    team_id uuid NOT NULL REFERENCES teams (id) ON DELETE RESTRICT,
    responsible_identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    name text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disabled_at timestamptz,
    UNIQUE (team_id, name),
    FOREIGN KEY (responsible_identity_id, team_id) REFERENCES memberships (identity_id, team_id) ON DELETE RESTRICT,
    CONSTRAINT service_accounts_name_valid CHECK (name = btrim(name) AND length(name) > 0),
    CONSTRAINT service_accounts_status_valid CHECK (status IN ('active', 'disabled')),
    CONSTRAINT service_accounts_disabled_time_valid CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    token_hash bytea NOT NULL UNIQUE,
    csrf_token_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    reauthenticated_until timestamptz,
    revoked_at timestamptz,
    CONSTRAINT sessions_token_hash_valid CHECK (octet_length(token_hash) > 0),
    CONSTRAINT sessions_csrf_token_hash_valid CHECK (octet_length(csrf_token_hash) > 0),
    CONSTRAINT sessions_expiry_valid CHECK (idle_expires_at > created_at AND absolute_expires_at > created_at AND idle_expires_at <= absolute_expires_at),
    CONSTRAINT sessions_last_seen_valid CHECK (last_seen_at >= created_at),
    CONSTRAINT sessions_reauthentication_valid CHECK (reauthenticated_until IS NULL OR reauthenticated_until > created_at),
    CONSTRAINT sessions_revocation_valid CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE TABLE one_time_codes (
    id uuid PRIMARY KEY,
    identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    email text NOT NULL,
    purpose text NOT NULL,
    code_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at timestamptz,
    revoked_at timestamptz,
    issued_by_identity_id uuid NOT NULL REFERENCES identities (id) ON DELETE RESTRICT,
    revoke_personal_keys_on_use boolean NOT NULL DEFAULT false,
    CONSTRAINT one_time_codes_email_normalized CHECK (email = lower(btrim(email)) AND length(email) > 0),
    CONSTRAINT one_time_codes_purpose_valid CHECK (purpose IN ('activation', 'password_reset')),
    CONSTRAINT one_time_codes_hash_valid CHECK (octet_length(code_hash) > 0),
    CONSTRAINT one_time_codes_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT one_time_codes_used_time_valid CHECK (used_at IS NULL OR used_at >= created_at),
    CONSTRAINT one_time_codes_revoked_time_valid CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CONSTRAINT one_time_codes_compromise_mode_valid CHECK (purpose = 'password_reset' OR NOT revoke_personal_keys_on_use)
);

CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    identity_id uuid REFERENCES identities (id) ON DELETE RESTRICT,
    service_account_id uuid REFERENCES service_accounts (id) ON DELETE RESTRICT,
    kind text NOT NULL,
    name text NOT NULL,
    prefix text NOT NULL,
    verification_hash bytea NOT NULL UNIQUE,
    status text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at timestamptz,
    revoked_at timestamptz,
    UNIQUE (identity_id, name),
    UNIQUE (service_account_id, name),
    CONSTRAINT api_keys_owner_valid CHECK (
        (kind = 'personal' AND identity_id IS NOT NULL AND service_account_id IS NULL)
        OR (kind = 'service' AND identity_id IS NULL AND service_account_id IS NOT NULL)
    ),
    CONSTRAINT api_keys_name_valid CHECK (name = btrim(name) AND length(name) > 0),
    CONSTRAINT api_keys_prefix_valid CHECK (length(prefix) BETWEEN 4 AND 32),
    CONSTRAINT api_keys_hash_valid CHECK (octet_length(verification_hash) > 0),
    CONSTRAINT api_keys_status_valid CHECK (status IN ('active', 'revoked')),
    CONSTRAINT api_keys_last_used_valid CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CONSTRAINT api_keys_revocation_valid CHECK ((status = 'revoked') = (revoked_at IS NOT NULL) AND (revoked_at IS NULL OR revoked_at >= created_at))
);
