package dev.bastion.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.net.URI;
import java.util.List;

/**
 * All Bastion-specific configuration, bound from {@code app.*} in application.yml.
 * Every value is overridable by environment variable — see .env.example and
 * docs/configuration.md for the full list with guidance.
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(
        /** Product name used in emails, the authenticator-app label and the passkey prompt. */
        @DefaultValue("Bastion") String name,
        /** Base64-encoded 256-bit HMAC key for signing access tokens. REQUIRED — no default. */
        String jwtSecret,
        /** Access-token lifetime in minutes (short on purpose; the refresh cookie does the heavy lifting). */
        @DefaultValue("15") int accessTokenMinutes,
        /** How the app is reached in a browser — every emailed link, and the passkey origin, is built from this. */
        @DefaultValue("http://localhost:5173") String baseUrl,
        /** From address stamped on every outgoing email. */
        @DefaultValue("Bastion <no-reply@bastion.local>") String mailFrom,
        /** Email-verification link lifetime in hours. */
        @DefaultValue("24") int verificationTokenHours,
        /** Password-reset link lifetime in minutes. */
        @DefaultValue("30") int resetTokenMinutes,
        /** Email-change confirmation link lifetime in hours. */
        @DefaultValue("24") int emailChangeTokenHours,
        @DefaultValue Session session,
        @DefaultValue Security security,
        @DefaultValue Passwords passwords,
        @DefaultValue Encryption encryption,
        @DefaultValue Signup signup,
        @DefaultValue Turnstile turnstile,
        @DefaultValue Passkeys passkeys,
        @DefaultValue Admin admin
) {

    public record Session(
            /** A session that hasn't refreshed in this many days ends (sliding). */
            @DefaultValue("14") int idleDays,
            /** A session ends this many days after sign-in however active it is (absolute). */
            @DefaultValue("30") int maxDays,
            /** How long a re-authentication ("sudo mode") unlocks sensitive actions. */
            @DefaultValue("10") int reauthMinutes,
            /** Email the owner when their account is signed in to from a device not seen before. */
            @DefaultValue("true") boolean newSignInAlerts
    ) {
    }

    public record Security(
            /**
             * Only enable behind a reverse proxy that RESETS X-Forwarded-For to the real
             * client address. Trusting the header on a directly-exposed app lets callers
             * spoof their own rate-limit key.
             */
            @DefaultValue("false") boolean trustForwardedFor,
            /** Origins allowed to call the API cross-origin with credentials. */
            @DefaultValue("http://localhost:5173") List<String> corsOrigins,
            /** Admin API requires a session that signed in with a second factor or a passkey. */
            @DefaultValue("true") boolean adminRequiresMfa,
            /** Turn off only in tests: every rate limiter and attempt budget. */
            @DefaultValue("true") boolean rateLimitsEnabled,
            /** Security-event rows older than this are purged nightly. */
            @DefaultValue("180") int auditRetentionDays,
            /** Largest request body the API will read, in bytes. */
            @DefaultValue("65536") long maxRequestBytes
    ) {
    }

    public record Passwords(
            /** NIST SP 800-63B-4 asks for 15 when a password is the only factor; 12 is a common floor. */
            @DefaultValue("12") int minLength,
            /** Upper bound keeps one hash affordable — Argon2 cost grows with input length. */
            @DefaultValue("128") int maxLength,
            /** Refuse passwords found in public breach corpora (HIBP k-anonymity; fails open). */
            @DefaultValue("true") boolean breachCheck
    ) {
    }

    public record Encryption(
            /** Base64 256-bit key for AES-GCM field encryption (TOTP secrets). REQUIRED. */
            String key,
            /** Comma-separated retired keys, still accepted for decryption during rotation. */
            @DefaultValue("") String previousKeys
    ) {
    }

    public record Signup(
            /** Initial state of the admin-controlled "new accounts" switch. */
            @DefaultValue("true") boolean openByDefault,
            /** Refuse addresses at known throwaway-mail providers. */
            @DefaultValue("true") boolean blockDisposable,
            /** Refuse domains that publish no mail exchanger (fails open on DNS trouble). */
            @DefaultValue("true") boolean checkMx,
            /** Unverified accounts older than this are deleted. */
            @DefaultValue("7") int purgeUnverifiedDays
    ) {
    }

    public record Turnstile(
            /** Cloudflare Turnstile public site key. Leave both blank to disable the CAPTCHA. */
            @DefaultValue("") String siteKey,
            /** Cloudflare Turnstile secret key. */
            @DefaultValue("") String secretKey
    ) {
        public boolean enabled() {
            return !secretKey.isBlank() && !siteKey.isBlank();
        }
    }

    public record Passkeys(
            /**
             * WebAuthn relying-party id. Defaults to the host of {@code app.base-url}; set it to
             * the registrable parent domain to share passkeys across subdomains.
             */
            @DefaultValue("") String rpId,
            /** Extra origins allowed in ceremonies (comma-separated), e.g. a second front-end host. */
            @DefaultValue("") List<String> extraOrigins
    ) {
    }

    public record Admin(
            /**
             * The first administrator: when an account with this address verifies its email
             * and no administrator exists yet, it is promoted. Never creates an account and
             * never logs a password.
             */
            @DefaultValue("") String bootstrapEmail
    ) {
    }

    /** Whether cookies should carry the Secure flag — follows how the app is reached. */
    public boolean secureCookies() {
        return baseUrl.startsWith("https://");
    }

    /** The WebAuthn relying-party id: configured, or the base URL's host. */
    public String rpId() {
        if (!passkeys.rpId().isBlank()) {
            return passkeys.rpId();
        }
        String host = URI.create(baseUrl).getHost();
        return host == null ? "localhost" : host;
    }
}
