package dev.bastion.audit;

/**
 * Everything the security log records. Stored by name, so values may be added
 * freely but never renamed (old rows would stop mapping).
 */
public enum SecurityEventType {
    // account lifecycle
    SIGN_UP,
    SIGN_UP_EXISTING_ACCOUNT,
    EMAIL_VERIFIED,
    EMAIL_CHANGE_REQUESTED,
    EMAIL_CHANGED,
    ACCOUNT_DELETED,
    ACCOUNT_EXPORTED,

    // sign-in
    SIGN_IN,
    SIGN_IN_FAILED,
    SIGN_IN_BLOCKED,
    SIGN_IN_REFUSED,
    MFA_FAILED,
    RECOVERY_CODE_USED,
    PASSKEY_SIGN_IN_FAILED,
    NEW_DEVICE_SIGN_IN,
    SIGN_OUT,

    // sessions
    SESSION_REVOKED,
    OTHER_SESSIONS_REVOKED,
    REFRESH_TOKEN_REUSE,
    REAUTHENTICATED,
    REAUTH_FAILED,

    // credentials
    PASSWORD_CHANGED,
    PASSWORD_RESET_REQUESTED,
    PASSWORD_RESET,
    MFA_ENABLED,
    MFA_DISABLED,
    RECOVERY_CODES_REGENERATED,
    PASSKEY_ADDED,
    PASSKEY_REMOVED,

    // administration
    ADMIN_BOOTSTRAPPED,
    ADMIN_ROLE_CHANGED,
    ADMIN_LOCKED,
    ADMIN_UNLOCKED,
    ADMIN_REVOKED_SESSIONS,
    ADMIN_RESET_MFA,
    ADMIN_DELETED_ACCOUNT,
    SIGNUPS_OPENED,
    SIGNUPS_CLOSED
}
