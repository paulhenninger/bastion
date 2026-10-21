package dev.bastion.security;

import dev.bastion.config.AppProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Locale;

/**
 * Sign-in attempts per <em>account</em> (as typed), the dimension the per-IP limit
 * is blind to: a botnet spraying passwords at one address from a thousand IPs never
 * fills any IP bucket, but it fills this one after ten guesses.
 *
 * <p><b>Charged before the password is checked, refunded on success.</b> Checking
 * first and recording failures afterwards has a race: a burst of parallel requests
 * all pass the check before any failure lands, and the "ten guesses" become
 * hundreds. Charging up front makes the budget atomic. A completed sign-in clears
 * it, so in effect only failures count and a busy shared NAT is never blocked.
 *
 * <p>Keyed on the address exactly as typed and charged whether or not an account
 * exists — a 429 must not reveal which addresses are registered. A soft lock that
 * lifts by itself: a hard lockout would let anyone who knows an address deny its
 * owner service.
 */
@Component
public class LoginThrottle {

    static final int MAX_ATTEMPTS = 10;
    static final Duration WINDOW = Duration.ofMinutes(15);

    private final WindowCounter attempts = new WindowCounter(WINDOW, 100_000);
    private final boolean enabled;

    public LoginThrottle(AppProperties props) {
        this.enabled = props.security().rateLimitsEnabled();
    }

    /** Charges one attempt; false when the account's budget is already spent. */
    public boolean tryAcquire(String email) {
        return !enabled || attempts.increment(key(email)) <= MAX_ATTEMPTS;
    }

    /** A sign-in completed: the owner shouldn't stay penalised for earlier typos. */
    public void recordSuccess(String email) {
        attempts.reset(key(email));
    }

    private static String key(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }
}
