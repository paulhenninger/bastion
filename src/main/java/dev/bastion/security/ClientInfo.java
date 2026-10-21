package dev.bastion.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.regex.Pattern;

/**
 * Who is on the other end of a request: their address and their user agent, as
 * trusted by everything that rate-limits, logs or alerts by origin. One place,
 * because three copies of the forwarded-header rule would be three chances to get
 * it wrong.
 *
 * <p>The leftmost {@code X-Forwarded-For} hop is only believed when
 * {@code app.security.trust-forwarded-for} is on — which is only correct behind an
 * outermost proxy that RESETS the header (the bundled nginx.conf does). Even then,
 * anything that doesn't parse as an IP literal falls back to the socket address,
 * so a misconfigured proxy can't feed junk into the limiters' tables.
 */
public record ClientInfo(String ip, String userAgent) {

    private static final Pattern IP_LITERAL =
            Pattern.compile("^(\\d{1,3}(\\.\\d{1,3}){3}|[0-9a-fA-F:.]{2,45})$");
    private static final int MAX_USER_AGENT = 255;

    /** Set once at startup from configuration (see SecurityConfig). */
    private static volatile boolean trustForwardedFor;

    public static void trustForwardedFor(boolean trust) {
        trustForwardedFor = trust;
    }

    public static ClientInfo of(HttpServletRequest request) {
        return new ClientInfo(ip(request), userAgent(request));
    }

    /** The current request's client, or an empty one off the request thread. */
    public static ClientInfo current() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return of(attributes.getRequest());
        }
        return new ClientInfo(null, null);
    }

    public static String ip(HttpServletRequest request) {
        if (trustForwardedFor) {
            String header = request.getHeader("X-Forwarded-For");
            if (header != null && !header.isBlank()) {
                String hop = header.split(",")[0].strip();
                if (hop.length() <= 45 && IP_LITERAL.matcher(hop).matches()) {
                    return hop;
                }
            }
        }
        return request.getRemoteAddr();
    }

    private static String userAgent(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        if (ua == null || ua.isBlank()) {
            return null;
        }
        // Control characters would let a caller forge lines in logs and emails.
        String clean = ua.replaceAll("\\p{Cntrl}", " ").strip();
        return clean.length() <= MAX_USER_AGENT ? clean : clean.substring(0, MAX_USER_AGENT);
    }
}
