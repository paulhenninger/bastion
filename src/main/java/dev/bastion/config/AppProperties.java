package dev.bastion.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * All Bastion-specific configuration, bound from {@code app.*} in application.yml.
 * Every value is overridable by environment variable — see .env.example.
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(
        /** Base64-encoded 256-bit HMAC key for signing access tokens. REQUIRED — no default. */
        String jwtSecret,
        /** Access-token lifetime in minutes (short on purpose; the refresh cookie does the heavy lifting). */
        int accessTokenMinutes,
        /** Refresh-token lifetime in days. */
        int refreshTokenDays,
        /** How the app is reached in a browser — every emailed link is built from this. */
        String baseUrl,
        /** From address stamped on every outgoing email. */
        String mailFrom,
        /** Email-verification link lifetime in hours. */
        int verificationTokenHours,
        /** Password-reset link lifetime in minutes. */
        int resetTokenMinutes
) {
}
