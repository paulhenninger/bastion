package dev.bastion.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Fixed-window rate limiting per IP per auth endpoint. In-memory by design — this
 * starter assumes a single instance (swap in Redis when you scale out).
 *
 * <p>Two details that are easy to get wrong:
 * <ul>
 *   <li>The client IP is the <b>leftmost X-Forwarded-For hop</b> only when your outermost
 *       reverse proxy RESETS that header to the real remote address. If you don't control
 *       a proxy that does, leave {@code app.security.trust-forwarded-for} off (the default)
 *       and the socket address is used — otherwise any caller can spoof their own key.</li>
 *   <li>{@code MAX_TRACKED_KEYS} is a hard bound, not just a prune trigger: under the very
 *       traffic the cap exists for (a spray across rotating IPs) every entry is fresh, so
 *       pruning only expired entries would remove nothing. Oldest windows are evicted too —
 *       handing one caller back a window they could have had by waiting beats letting an
 *       attacker spend the server's memory.</li>
 * </ul>
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    static final int MAX_TRACKED_KEYS = 50_000;
    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final int limitPerWindow;
    private final boolean trustForwardedFor;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimitFilter(@Value("${app.security.trust-forwarded-for:false}") boolean trustForwardedFor,
                           @Value("${app.security.auth-requests-per-window:30}") int limitPerWindow) {
        this.trustForwardedFor = trustForwardedFor;
        this.limitPerWindow = limitPerWindow;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/v1/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String key = clientIp(request) + "|" + request.getRequestURI();
        Instant now = Instant.now();

        Window window = windows.compute(key, (k, w) ->
                (w == null || w.start.plus(WINDOW).isBefore(now)) ? new Window(now) : w);

        if (window.count.incrementAndGet() > limitPerWindow) {
            response.setStatus(429);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"message\":\"Too many requests. Try again later.\"}");
            return;
        }

        if (windows.size() > MAX_TRACKED_KEYS) {
            evict(now);
        }
        chain.doFilter(request, response);
    }

    private String clientIp(HttpServletRequest request) {
        if (trustForwardedFor) {
            String header = request.getHeader("X-Forwarded-For");
            if (header != null && !header.isBlank()) {
                return header.split(",")[0].trim();
            }
        }
        return request.getRemoteAddr();
    }

    private synchronized void evict(Instant now) {
        if (windows.size() <= MAX_TRACKED_KEYS) {
            return;
        }
        windows.entrySet().removeIf(e -> e.getValue().start.plus(WINDOW).isBefore(now));
        // Under a spray every window is fresh; enforce the bound by dropping the oldest.
        while (windows.size() > MAX_TRACKED_KEYS) {
            windows.entrySet().stream()
                    .min(Comparator.comparing(e -> e.getValue().start))
                    .ifPresent(oldest -> windows.remove(oldest.getKey()));
        }
    }

    private static final class Window {
        final Instant start;
        final AtomicInteger count = new AtomicInteger();

        Window(Instant start) {
            this.start = start;
        }
    }
}
