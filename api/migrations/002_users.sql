-- Local users, roles and 2FA (the PAMdora model; Entra ID SSO deferred, Craig 2026-09-30).
-- Permissions -> roles -> users. Sessions are server-side, referenced by an HttpOnly cookie.

CREATE TABLE role (
    role_key     text PRIMARY KEY,
    name         text NOT NULL,
    description  text,
    is_system    boolean NOT NULL DEFAULT false
);

CREATE TABLE role_permission (
    role_key    text NOT NULL REFERENCES role (role_key) ON DELETE CASCADE,
    permission  text NOT NULL,
    PRIMARY KEY (role_key, permission)
);

CREATE TABLE app_user (
    user_id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username               text NOT NULL,
    full_name              text,
    email                  text,
    password_hash          text NOT NULL,
    status                 text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    must_change_password   boolean NOT NULL DEFAULT true,
    failed_login_attempts  int NOT NULL DEFAULT 0,
    locked_until           timestamptz,
    failed_mfa_attempts    int NOT NULL DEFAULT 0,
    mfa_locked_until       timestamptz,
    last_login_at          timestamptz,
    password_changed_at    timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    created_by             text,
    CONSTRAINT app_user_username_format CHECK (username ~ '^[a-z0-9][a-z0-9._-]{1,63}$')
);
CREATE UNIQUE INDEX app_user_username ON app_user (lower(username));

CREATE TABLE user_role (
    user_id   uuid NOT NULL REFERENCES app_user (user_id) ON DELETE CASCADE,
    role_key  text NOT NULL REFERENCES role (role_key) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_key)
);

CREATE TABLE mfa_device (
    device_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES app_user (user_id) ON DELETE CASCADE,
    name          text NOT NULL DEFAULT 'Authenticator app',
    totp_secret   text NOT NULL,          -- sealed with AES-GCM (IPAM_SECRET_KEY), never stored in clear
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'revoked')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    activated_at  timestamptz,
    last_used_at  timestamptz,
    last_step     bigint                  -- last accepted TOTP time-step: stops a code being replayed
);
CREATE INDEX mfa_device_user ON mfa_device (user_id) WHERE status = 'active';

CREATE TABLE mfa_backup_code (
    code_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES app_user (user_id) ON DELETE CASCADE,
    code_hash  text NOT NULL,
    used_at    timestamptz
);

CREATE TABLE user_session (
    session_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid NOT NULL REFERENCES app_user (user_id) ON DELETE CASCADE,
    token_hash     text NOT NULL UNIQUE,
    state          text NOT NULL CHECK (state IN ('mfa-pending', 'active', 'revoked')),
    auth_method    text NOT NULL,          -- password | password+totp | password+backup-code
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,   -- absolute limit
    step_up_at     timestamptz,            -- last fresh 2FA code for high-risk actions
    source_ip      inet,
    user_agent     text
);
CREATE INDEX user_session_user ON user_session (user_id) WHERE state <> 'revoked';

-- API keys now have an issuer and can be revoked from the UI.
ALTER TABLE api_key ADD COLUMN created_by text;
