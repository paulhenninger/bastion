package dev.bastion.security;

import dev.bastion.common.ApiException;
import dev.bastion.config.AppProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Per-account budgets for guessable secrets checked <em>after</em> sign-in or
 * mid-sign-in: the password on re-authentication, TOTP and recovery codes, the
 * password on email verification.
 *
 * <p>Why these need their own budget: a six-digit code is a 1-in-a-million guess,
 * and every fresh sign-in mints a fresh challenge. Without a budget that belongs
 * to the <em>account</em>, someone who has the password could grind the code
 * indefinitely, and someone holding a stolen access token could grind the password
 * through the re-auth endpoint.
 *
 * <p>Charged before the secret is checked and refunded on success — atomic, so a
 * burst of parallel guesses can't slip past (see {@link LoginThrottle}). Held in
 * memory, so it stands even when a refused request rolls back its transaction.
 */
@Component
public class AttemptGuard {

    static final int MAX_ATTEMPTS = 5;
    static final Duration WINDOW = Duration.ofMinutes(15);

    private final WindowCounter attempts = new WindowCounter(WINDOW, 100_000);
    private final boolean enabled;

    public AttemptGuard(AppProperties props) {
        this.enabled = props.security().rateLimitsEnabled();
    }

    /** Charges one attempt against {@code key}; throws 429 once the budget is spent. */
    public void acquire(String key) {
        if (enabled && attempts.increment(key) > MAX_ATTEMPTS) {
            throw ApiException.tooManyRequests("Too many incorrect attempts. Wait 15 minutes and try again.");
        }
    }

    /** The secret was right: give the attempt back. */
    public void clear(String key) {
        attempts.reset(key);
    }
}
