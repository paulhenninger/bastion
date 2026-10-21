-- Bastion 2.0: two-factor authentication, passkeys, session tracking, the
-- security event log, email change and admin settings.
--
-- Every secret at rest is hashed (SHA-256 for high-entropy tokens, Argon2id for
-- passwords) or encrypted (AES-256-GCM for TOTP secrets, which must be read back).

-- Values below are written and read in UTC; the JDBC URL pins the session the same way.
SET time_zone = '+00:00';

-- ---------------------------------------------------------------------- users

-- TIMESTAMP stops at 2038-01-19; DATETIME(6) does not. Converted under UTC above.
ALTER TABLE users
    MODIFY password_hash VARCHAR(255) NOT NULL,   -- Argon2id encodings run ~130 chars
    MODIFY last_login_at DATETIME(6) NULL,
    MODIFY created_at    DATETIME(6) NOT NULL,
    MODIFY updated_at    DATETIME(6) NOT NULL,
    ADD COLUMN password_changed_at  DATETIME(6)  NULL,
    -- AES-GCM ciphertext (see DataCipher); null when TOTP is off.
    ADD COLUMN totp_secret          VARCHAR(255) NULL,
    -- Generated at setup, promoted to totp_secret only once a code proves it works.
    ADD COLUMN totp_pending_secret  VARCHAR(255) NULL,
    -- Last accepted TOTP time step: a code is good exactly once (RFC 6238 §5.2).
    ADD COLUMN totp_last_step       BIGINT       NULL,
    -- Random, stable, non-identifying WebAuthn user handle (never the email or id).
    ADD COLUMN webauthn_user_handle VARCHAR(64)  NULL,
    ADD CONSTRAINT uq_users_webauthn_handle UNIQUE (webauthn_user_handle);

CREATE INDEX ix_users_enabled_created ON users (enabled, created_at);

-- ------------------------------------------------------------------- sessions

-- One row per sign-in. Refresh tokens rotate underneath it; the access token
-- carries its public id, so revoking the row ends the session on the very next
-- request rather than when the access token expires.
CREATE TABLE user_sessions (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    public_id     VARCHAR(43)  NOT NULL,
    user_id       BIGINT       NOT NULL,
    auth_method   VARCHAR(20)  NOT NULL,
    -- Signed in with a second factor or a passkey (what the admin API requires).
    strong_auth   BOOLEAN      NOT NULL DEFAULT FALSE,
    ip            VARCHAR(45)  NULL,
    user_agent    VARCHAR(255) NULL,
    created_at    DATETIME(6)  NOT NULL,
    last_seen_at  DATETIME(6)  NOT NULL,
    -- Absolute end of the session, however often it refreshes.
    expires_at    DATETIME(6)  NOT NULL,
    -- Last re-authentication ("sudo mode") for sensitive actions.
    reauth_at     DATETIME(6)  NULL,
    revoked_at    DATETIME(6)  NULL,
    CONSTRAINT uq_user_sessions_public_id UNIQUE (public_id),
    CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX ix_user_sessions_user ON user_sessions (user_id, revoked_at);
CREATE INDEX ix_user_sessions_expires ON user_sessions (expires_at);

-- Existing refresh tokens predate session tracking and cannot be attached to a
-- session; everyone signs in once more after this upgrade. (The condition is
-- every row: ids start at 1.)
DELETE FROM refresh_tokens WHERE id > 0;

ALTER TABLE refresh_tokens
    MODIFY expires_at DATETIME(6) NOT NULL,
    MODIFY revoked_at DATETIME(6) NULL,
    MODIFY created_at DATETIME(6) NOT NULL,
    ADD COLUMN session_id BIGINT NOT NULL,
    ADD CONSTRAINT fk_refresh_tokens_session FOREIGN KEY (session_id) REFERENCES user_sessions (id) ON DELETE CASCADE;

-- -------------------------------------------------------------- email tokens

ALTER TABLE email_verification_tokens
    MODIFY expires_at DATETIME(6) NOT NULL,
    MODIFY used_at    DATETIME(6) NULL,
    MODIFY created_at DATETIME(6) NOT NULL,
    -- The password chosen in the signup that sent this link. Verification applies
    -- the pending password the person proves they know — never simply the latest
    -- one — which is what defeats account pre-hijacking (see AuthService).
    ADD COLUMN password_hash VARCHAR(255) NULL;

CREATE INDEX ix_verification_tokens_user ON email_verification_tokens (user_id, used_at);

ALTER TABLE password_reset_tokens
    MODIFY expires_at DATETIME(6) NOT NULL,
    MODIFY used_at    DATETIME(6) NULL,
    MODIFY created_at DATETIME(6) NOT NULL;

CREATE INDEX ix_reset_tokens_user ON password_reset_tokens (user_id, used_at);

CREATE TABLE email_change_tokens (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT       NOT NULL,
    new_email  VARCHAR(255) NOT NULL,
    token_hash CHAR(64)     NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    used_at    DATETIME(6)  NULL,
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT uq_email_change_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_email_change_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX ix_email_change_tokens_expires ON email_change_tokens (expires_at);

-- ------------------------------------------------------------------------ MFA

CREATE TABLE mfa_recovery_codes (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT      NOT NULL,
    code_hash  CHAR(64)    NOT NULL,
    used_at    DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT uq_mfa_recovery_codes UNIQUE (user_id, code_hash),
    CONSTRAINT fk_mfa_recovery_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

-- The half-finished sign-in between "password correct" and "second factor correct".
CREATE TABLE mfa_challenges (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT      NOT NULL,
    token_hash CHAR(64)    NOT NULL,
    attempts   INT         NOT NULL DEFAULT 0,
    expires_at DATETIME(6) NOT NULL,
    used_at    DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT uq_mfa_challenges_hash UNIQUE (token_hash),
    CONSTRAINT fk_mfa_challenges_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX ix_mfa_challenges_expires ON mfa_challenges (expires_at);

-- ------------------------------------------------------------------- passkeys

CREATE TABLE webauthn_credentials (
    id                       BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id                  BIGINT        NOT NULL,
    -- Credential ids can run to 1023 bytes; the unique index is on their hash.
    credential_id            VARCHAR(1400) NOT NULL,
    credential_id_hash       CHAR(64)      NOT NULL,
    attested_credential_data VARBINARY(4096) NOT NULL,
    sign_count               BIGINT        NOT NULL,
    uv_initialized           BOOLEAN       NOT NULL,
    backup_eligible          BOOLEAN       NOT NULL,
    backed_up                BOOLEAN       NOT NULL,
    transports               VARCHAR(255)  NULL,
    aaguid                   CHAR(36)      NULL,
    label                    VARCHAR(100)  NOT NULL,
    created_at               DATETIME(6)   NOT NULL,
    last_used_at             DATETIME(6)   NULL,
    CONSTRAINT uq_webauthn_credentials_id UNIQUE (credential_id_hash),
    CONSTRAINT fk_webauthn_credentials_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX ix_webauthn_credentials_user ON webauthn_credentials (user_id);

CREATE TABLE webauthn_challenges (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    challenge  VARCHAR(64) NOT NULL,
    purpose    VARCHAR(20) NOT NULL,
    user_id    BIGINT      NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at    DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT uq_webauthn_challenges UNIQUE (challenge),
    CONSTRAINT fk_webauthn_challenges_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX ix_webauthn_challenges_expires ON webauthn_challenges (expires_at);

-- ------------------------------------------------------------ security events

-- Append-only. user_id deliberately has no foreign key: the record of what
-- happened to an account must outlive the account. Rows are purged after the
-- configured retention (they hold email and IP addresses).
CREATE TABLE security_events (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    occurred_at   DATETIME(6)  NOT NULL,
    type          VARCHAR(40)  NOT NULL,
    user_id       BIGINT       NULL,
    subject_email VARCHAR(255) NULL,
    actor_user_id BIGINT       NULL,
    ip            VARCHAR(45)  NULL,
    user_agent    VARCHAR(255) NULL,
    detail        VARCHAR(255) NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE INDEX ix_security_events_occurred ON security_events (occurred_at);
CREATE INDEX ix_security_events_user ON security_events (user_id, occurred_at);
CREATE INDEX ix_security_events_email ON security_events (subject_email, occurred_at);
CREATE INDEX ix_security_events_ip ON security_events (ip, occurred_at);
CREATE INDEX ix_security_events_type ON security_events (type, occurred_at);

-- -------------------------------------------------------------- app settings

-- Runtime switches an administrator can flip without a redeploy.
CREATE TABLE app_settings (
    name       VARCHAR(64)  NOT NULL PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL,
    updated_at DATETIME(6)  NOT NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
