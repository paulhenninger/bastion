package dev.bastion.session;

/** How a session was established — shown to the user, recorded in the security log. */
public enum AuthMethod {
    /** Password only (the account has no second factor). */
    PASSWORD(false),
    /** Password plus an authenticator-app code. */
    PASSWORD_TOTP(true),
    /** Password plus a one-time recovery code. */
    PASSWORD_RECOVERY_CODE(true),
    /** A passkey with user verification — possession plus biometric/PIN in one step. */
    PASSKEY(true),
    /** The email-verification link that activated a new account (plus its password). */
    EMAIL_VERIFICATION(false);

    private final boolean strong;

    AuthMethod(boolean strong) {
        this.strong = strong;
    }

    /** Two independent factors were proven — what the admin API requires. */
    public boolean isStrong() {
        return strong;
    }
}
