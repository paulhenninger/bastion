package dev.bastion.email;

import dev.bastion.config.AppProperties;
import dev.bastion.security.WindowCounter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Locale;

/**
 * At most {@value #MAX_PER_HOUR} messages to any one address per hour, however many
 * IPs ask. The per-IP limits can't see a botnet flooding one victim's inbox with reset
 * links (or running up the SES bill); this can.
 *
 * <p><b>A refusal must be invisible to the caller</b> — callers skip the send and carry
 * on exactly as if it went, or the limiter would reveal which addresses are registered.
 */
@Component
class EmailRateLimiter {

    static final int MAX_PER_HOUR = 10;
    private static final Logger log = LoggerFactory.getLogger(EmailRateLimiter.class);

    private final WindowCounter sends = new WindowCounter(Duration.ofHours(1), 100_000);
    private final boolean enabled;

    EmailRateLimiter(AppProperties props) {
        this.enabled = props.security().rateLimitsEnabled();
    }

    boolean allowSend(String email) {
        if (!enabled || email == null) {
            return true;
        }
        if (sends.increment(email.trim().toLowerCase(Locale.ROOT)) > MAX_PER_HOUR) {
            log.warn("Per-recipient mail cap reached — suppressing a send");
            return false;
        }
        return true;
    }
}
