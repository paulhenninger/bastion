package dev.bastion.security;

import dev.bastion.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.function.UnaryOperator;

/**
 * Whether a password appears in Have I Been Pwned's Pwned Passwords corpus — the
 * list attackers try first against every site, so a password on it is refused
 * however long or unusual it looks (NIST SP 800-63B §3.1.1.2).
 *
 * <p><b>The password never leaves the server.</b> k-anonymity: only the first five
 * hex characters of its SHA-1 are sent; the service answers with every known suffix
 * sharing that prefix (hundreds), and the match happens here. Padding is requested
 * so the response size says nothing either.
 *
 * <p><b>Fails open.</b> If the service can't answer within two seconds the password
 * is accepted: nobody gains from an outage (length rules still apply), whereas
 * failing closed would let a third party's downtime stop every signup.
 */
@Component
public class BreachedPasswords {

    private static final Logger log = LoggerFactory.getLogger(BreachedPasswords.class);
    private static final String RANGE_URL = "https://api.pwnedpasswords.com/range/";
    private static final Duration TIMEOUT = Duration.ofSeconds(2);
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

    private final boolean enabled;
    /** Given the five-character prefix, returns lines of {@code SUFFIX:COUNT}. */
    private final UnaryOperator<String> range;

    @Autowired
    public BreachedPasswords(AppProperties props) {
        this(props.passwords().breachCheck(), BreachedPasswords::fetch);
    }

    BreachedPasswords(boolean enabled, UnaryOperator<String> range) {
        this.enabled = enabled;
        this.range = range;
    }

    public boolean isBreached(String password) {
        if (!enabled || password == null || password.isEmpty()) {
            return false;
        }
        String hash = sha1Hex(password);
        String prefix = hash.substring(0, 5);
        String suffix = hash.substring(5);
        try {
            for (String line : range.apply(prefix).split("\\R")) {
                int colon = line.indexOf(':');
                // Padding lines carry a count of zero: present in the answer, never breached.
                if (colon == suffix.length() && line.regionMatches(true, 0, suffix, 0, colon)
                        && !"0".equals(line.substring(colon + 1).trim())) {
                    return true;
                }
            }
        } catch (RuntimeException e) {
            log.warn("Breached-password check unavailable, allowing: {}", e.toString());
        }
        return false;
    }

    private static String fetch(String prefix) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(RANGE_URL + prefix))
                    .timeout(TIMEOUT)
                    .header("Add-Padding", "true")
                    .header("User-Agent", "bastion-password-check")
                    .GET().build();
            HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("status " + response.statusCode());
            }
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static String sha1Hex(String password) {
        try {
            // SHA-1 because that is how HIBP keys its corpus. This is a lookup key for
            // someone else's service, never how a password is stored (that's Argon2id).
            MessageDigest lookupKey = MessageDigest.getInstance("SHA-1"); // NOSONAR HIBP's lookup key
            byte[] digest = lookupKey.digest(password.getBytes(StandardCharsets.UTF_8)); // NOSONAR
            return HexFormat.of().formatHex(digest).toUpperCase(Locale.ROOT);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
