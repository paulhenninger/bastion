package dev.bastion.security;

import dev.bastion.common.ApiException;
import dev.bastion.config.AppProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * The rules for a password being <em>set</em> — at signup, on a change, on a reset.
 * Following NIST SP 800-63B: length is what matters, composition rules ("one
 * uppercase, one symbol") are not imposed, and a password known to be breached is
 * refused. Never applied to a password being <em>checked</em> (sign-in): refusing
 * one there would turn a wrong guess into a different, informative error.
 *
 * <p>Length is counted in Unicode code points, so an emoji is one character, not two.
 */
@Component
public class PasswordPolicy {

    private final int minLength;
    private final int maxLength;
    private final BreachedPasswords breached;

    public PasswordPolicy(AppProperties props, BreachedPasswords breached) {
        this.minLength = props.passwords().minLength();
        this.maxLength = props.passwords().maxLength();
        this.breached = breached;
    }

    public int minLength() {
        return minLength;
    }

    public int maxLength() {
        return maxLength;
    }

    /** Throws a 400 explaining what's wrong, or returns quietly. */
    public void check(String password, String email) {
        if (password == null) {
            throw ApiException.badRequest("A password is required");
        }
        int length = password.codePointCount(0, password.length());
        if (length < minLength) {
            throw ApiException.badRequest("Password must be at least " + minLength + " characters");
        }
        if (length > maxLength) {
            throw ApiException.badRequest("Password must be at most " + maxLength + " characters");
        }
        if (email != null && containsAccountName(password, email)) {
            throw ApiException.badRequest("Password must not contain your email address");
        }
        if (breached.isBreached(password)) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "That password has appeared in a data breach elsewhere, so attackers already try it. "
                            + "Please choose a different one.", ApiException.BREACHED_PASSWORD);
        }
    }

    private static boolean containsAccountName(String password, String email) {
        String lower = password.toLowerCase(Locale.ROOT);
        String address = email.toLowerCase(Locale.ROOT);
        int at = address.indexOf('@');
        String local = at > 0 ? address.substring(0, at) : address;
        // A short local part ("jo@") would match too much to mean anything.
        return lower.contains(address) || (local.length() >= 4 && lower.contains(local));
    }
}
