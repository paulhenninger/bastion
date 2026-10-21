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
 * lifts by itself.
 *
 * <p><b>Known devices have a budget of their own.</b> On its own, a per-account budget
 * lets anyone who knows an address keep its owner locked out by spending it every
 * window. A browser that has signed in to the account before presents a
 * {@link DeviceCookies device cookie}; its attempts are charged to that device instead,
 * so the owner gets in however hard someone else is hammering the account.
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

    /**
     * Charges one attempt — to {@code knownDevice} when the browser proved it has signed
     * in to this account before, otherwise to the account. False when that budget is spent.
     */
    public boolean tryAcquire(String email, DeviceCookies.Device knownDevice) {
        return !enabled || attempts.increment(key(email, knownDevice)) <= MAX_ATTEMPTS;
    }

    /** A sign-in completed: the owner shouldn't stay penalised for earlier typos. */
    public void recordSuccess(String email, DeviceCookies.Device knownDevice) {
        attempts.reset(key(email, null));
        if (knownDevice != null) {
            attempts.reset(key(email, knownDevice));
        }
    }

    private static String key(String email, DeviceCookies.Device knownDevice) {
        return knownDevice != null
                ? "device:" + knownDevice.id()
                : "account:" + (email == null ? "" : email.trim().toLowerCase(Locale.ROOT));
    }
}
