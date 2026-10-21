package dev.bastion.security;

import dev.bastion.config.AppProperties;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

/**
 * Per-IP request limits, tightest on the endpoints that cost the server (Argon2,
 * email) or that an attacker would grind. A first, coarse layer: per-account
 * failure throttling ({@link LoginThrottle}, {@link AttemptGuard}) and the
 * per-recipient mail cap sit behind it, because an attacker rotating IPs never
 * fills any single bucket here.
 *
 * <p><b>Signup counts accounts, not keystrokes.</b> Its tight hourly limit is charged
 * up front like the rest, but refunded when the request is refused as invalid (a
 * breached or too-short password, a disposable address): otherwise a person who tries
 * five passwords the breach check rejects can't sign up for an hour. Refused attempts
 * still meet a looser ceiling of their own, so they can't be sent without limit.
 *
 * <p>Buckets are keyed on the <em>rule</em>, never the raw URI: a request whose
 * path is spelled oddly still lands in the API-wide bucket rather than a fresh one
 * of its own. (Spring Security's firewall already rejects {@code ;}, {@code //} and
 * encoded slashes before this runs.)
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    static final int MAX_TRACKED_KEYS = 50_000;
    static final int SIGNUP_ATTEMPTS_PER_HOUR = 30;
    private static final String AUTH = "/api/v1/auth/";

    /** First match wins; the last rule is the API-wide ceiling. */
    private final List<Rule> rules = List.of(
            new Rule("signup", "POST", AUTH + "signup", 5, Duration.ofHours(1), SIGNUP_ATTEMPTS_PER_HOUR),
            new Rule("login", "POST", AUTH + "login", 20, Duration.ofMinutes(15)),
            new Rule("mfa", "POST", AUTH + "mfa", 20, Duration.ofMinutes(15)),
            new Rule("forgot", "POST", AUTH + "forgot-password", 5, Duration.ofMinutes(15)),
            new Rule("resend", "POST", AUTH + "resend-verification", 5, Duration.ofMinutes(15)),
            new Rule("reset", "POST", AUTH + "reset-password", 10, Duration.ofMinutes(15)),
            new Rule("verify", "POST", AUTH + "verify-email", 20, Duration.ofMinutes(15)),
            new Rule("email-change", "POST", AUTH + "confirm-email-change", 10, Duration.ofMinutes(15)),
            new Rule("passkey", "POST", AUTH + "passkey/", 60, Duration.ofMinutes(15)),
            new Rule("refresh", "POST", AUTH + "refresh", 300, Duration.ofMinutes(15)),
            new Rule("auth", null, AUTH, 120, Duration.ofMinutes(15)),
            new Rule("reauth", "POST", "/api/v1/users/me/reauth", 20, Duration.ofMinutes(15)),
            new Rule("api", null, "/api/", 3000, Duration.ofMinutes(15)));

    private final boolean enabled;
    private final MeterRegistry meters;

    public RateLimitFilter(AppProperties props, MeterRegistry meters) {
        this.enabled = props.security().rateLimitsEnabled();
        this.meters = meters;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !enabled || !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI();
        for (Rule rule : rules) {
            if (rule.matches(request.getMethod(), path)) {
                String key = ClientInfo.ip(request);
                if (rule.attempts != null && rule.attempts.increment(key) > rule.attemptLimit) {
                    reject(response, rule, rule.attempts, key);
                    return;
                }
                if (rule.counter.increment(key) > rule.limit) {
                    reject(response, rule, rule.counter, key);
                    return;
                }
                chain.doFilter(request, response);
                if (rule.attempts != null && response.getStatus() == HttpServletResponse.SC_BAD_REQUEST) {
                    rule.counter.decrement(key); // refused as invalid: no account was created
                }
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, Rule rule, WindowCounter counter, String key) throws IOException {
        meters.counter("bastion.ratelimit.rejected", "rule", rule.name).increment();
        response.setStatus(429);
        response.setHeader("Retry-After", String.valueOf(counter.secondsUntilReset(key)));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"message\":\"Too many requests. Try again later.\",\"code\":\"RATE_LIMITED\"}");
    }

    private static final class Rule {
        final String name;
        final String method;
        final String path;
        final int limit;
        final WindowCounter counter;
        /** When set: every attempt counts here, and invalid ones are refunded from {@link #counter}. */
        final WindowCounter attempts;
        final int attemptLimit;

        Rule(String name, String method, String path, int limit, Duration window) {
            this(name, method, path, limit, window, 0);
        }

        Rule(String name, String method, String path, int limit, Duration window, int attemptLimit) {
            this.name = name;
            this.method = method;
            this.path = path;
            this.limit = limit;
            this.counter = new WindowCounter(window, MAX_TRACKED_KEYS);
            this.attempts = attemptLimit > 0 ? new WindowCounter(window, MAX_TRACKED_KEYS) : null;
            this.attemptLimit = attemptLimit;
        }

        boolean matches(String requestMethod, String requestPath) {
            if (method != null && !method.equals(requestMethod)) {
                return false;
            }
            return path.endsWith("/") ? requestPath.startsWith(path) : requestPath.equals(path);
        }
    }
}
