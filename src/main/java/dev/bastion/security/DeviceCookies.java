package dev.bastion.security;

import dev.bastion.config.AppProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * Device cookies (OWASP, "Slow down online guessing attacks with device cookies").
 *
 * <p>A per-account sign-in budget stops password spraying, but on its own it hands
 * anyone who knows an address a way to lock its owner out: spend the budget every 15
 * minutes and the owner can never sign in. A device cookie fixes that. After a
 * successful sign-in the browser gets a signed token naming the account; sign-ins that
 * present it for the same account draw on a budget of their own (see
 * {@link LoginThrottle}), so an attacker exhausting the shared budget only blocks
 * browsers that have never signed in to the account.
 *
 * <p>It is not a credential and grants nothing but that separate budget: a stolen one
 * buys its thief ten guesses per window, exactly what an untrusted client gets. Signed
 * with a key derived from {@code JWT_SECRET} (rotating that secret just makes every
 * browser untrusted once more). {@code HttpOnly}, {@code SameSite=Strict}, scoped to
 * the auth endpoints like the refresh cookie, and kept on sign-out — it identifies the
 * browser, not a session.
 */
@Component
public class DeviceCookies {

    public static final String NAME = "bastion_device";
    private static final String PATH = "/api/v1/auth";
    private static final Duration LIFETIME = Duration.ofDays(365);
    private static final int MAX_LENGTH = 200;

    /** A verified device cookie: the account it was issued to, and its unique id. */
    public record Device(long userId, String id) {
    }

    private final SecretKeySpec key;
    private final boolean secure;

    public DeviceCookies(AppProperties props) {
        // Domain-separated from the JWT signing key: same secret, different key.
        byte[] secret = Base64.getDecoder().decode(props.jwtSecret().trim());
        this.key = new SecretKeySpec(hmac(new SecretKeySpec(secret, "HmacSHA256"),
                "bastion device cookie v1"), "HmacSHA256");
        this.secure = props.secureCookies();
    }

    /** A fresh cookie for a browser that just completed a sign-in to {@code userId}. */
    public ResponseCookie issue(long userId) {
        String payload = userId + "." + Tokens.randomBase64Url(16);
        String value = payload + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(key, payload));
        return ResponseCookie.from(NAME, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite("Strict")
                .path(PATH)
                .maxAge(LIFETIME)
                .build();
    }

    /** The device, if {@code value} is a cookie this server issued. */
    public Optional<Device> verify(String value) {
        if (value == null || value.isEmpty() || value.length() > MAX_LENGTH) {
            return Optional.empty();
        }
        int last = value.lastIndexOf('.');
        int first = value.indexOf('.');
        if (first <= 0 || last <= first) {
            return Optional.empty();
        }
        String payload = value.substring(0, last);
        byte[] expected = hmac(key, payload);
        byte[] presented;
        try {
            presented = Base64.getUrlDecoder().decode(value.substring(last + 1));
        } catch (IllegalArgumentException _) {
            return Optional.empty();
        }
        if (!MessageDigest.isEqual(expected, presented)) {
            return Optional.empty();
        }
        try {
            return Optional.of(new Device(Long.parseLong(value.substring(0, first)), value.substring(first + 1, last)));
        } catch (NumberFormatException _) {
            return Optional.empty();
        }
    }

    private static byte[] hmac(SecretKeySpec key, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
