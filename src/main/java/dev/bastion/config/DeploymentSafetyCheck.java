package dev.bastion.config;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Refuses to start a real deployment on development settings.
 *
 * <p>The repository ships working defaults so {@code docker compose up} runs with no
 * setup: database passwords anyone can read in docker-compose.yml, and an
 * {@code http://} base URL. Those are harmless on a laptop and dangerous anywhere
 * else, and nothing about a deployment that "works" reveals them. So once
 * {@code APP_BASE_URL} names a host other than this machine, the app checks for them
 * at startup and refuses, listing every problem at once:
 *
 * <ul>
 *   <li>a plain-{@code http} base URL (the session cookies would not be {@code Secure},
 *       and passkeys need a secure origin);</li>
 *   <li>a database password that is empty or one of the published development ones;</li>
 *   <li>the same key used as {@code JWT_SECRET} and {@code DATA_ENCRYPTION_KEY}.</li>
 * </ul>
 *
 * <p>{@code ALLOW_DEVELOPMENT_SETTINGS=true} skips the check, for trying the app from
 * another device on a private network. Never set it on a deployment.
 */
@Component
public class DeploymentSafetyCheck {

    /** Every password the repository publishes: Compose defaults and the old single login. */
    static final Set<String> DEVELOPMENT_PASSWORDS = Set.of(
            "", "bastion", "bastion-app-local", "bastion-owner-local", "password", "root");

    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]", "::1");

    public DeploymentSafetyCheck(AppProperties props, Environment env) {
        if (env.getProperty("app.security.allow-development-settings", Boolean.class, false)) {
            return;
        }
        List<String> problems = problems(props.baseUrl(), props.jwtSecret(), props.encryption().key(),
                env.getProperty("spring.datasource.password"), env.getProperty("spring.flyway.password"));
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Refusing to start " + props.baseUrl() + " on development settings:\n  - "
                    + String.join("\n  - ", problems)
                    + "\nSee docs/operations.md#production-checklist.");
        }
    }

    /** What is unsafe about these settings for a deployment; empty when they are fine or the app is local. */
    static List<String> problems(String baseUrl, String jwtSecret, String encryptionKey,
                                 String dbPassword, String flywayPassword) {
        List<String> problems = new ArrayList<>();
        URI uri = URI.create(baseUrl.trim());
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(java.util.Locale.ROOT);
        if (LOCAL_HOSTS.contains(host)) {
            return problems;
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            problems.add("APP_BASE_URL must start with https:// (cookies are only Secure over https)");
        }
        if (dbPassword == null || DEVELOPMENT_PASSWORDS.contains(dbPassword)) {
            problems.add("DB_PASS is empty or a published development password");
        }
        if (flywayPassword != null && DEVELOPMENT_PASSWORDS.contains(flywayPassword)) {
            problems.add("SPRING_FLYWAY_PASSWORD is empty or a published development password");
        }
        if (jwtSecret != null && !jwtSecret.isBlank() && jwtSecret.trim().equals(
                encryptionKey == null ? null : encryptionKey.trim())) {
            problems.add("JWT_SECRET and DATA_ENCRYPTION_KEY must be different keys");
        }
        return problems;
    }
}
