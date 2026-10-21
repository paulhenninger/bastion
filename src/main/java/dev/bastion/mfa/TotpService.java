package dev.bastion.mfa;

import dev.bastion.config.AppProperties;
import dev.bastion.security.Tokens;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.OptionalLong;

/**
 * RFC 6238 TOTP with the parameters every authenticator app defaults to: HMAC-SHA1,
 * 6 digits, 30-second steps. Implemented directly — it is HMAC over a time counter
 * plus base32 — rather than taking a dependency for forty lines.
 *
 * <p>SHA-1 here is not a weakness: TOTP's security rests on HMAC, and HMAC-SHA1
 * remains sound. SHA-256 variants exist in the RFC but several popular apps
 * silently ignore the {@code algorithm} parameter, which would lock users out.
 */
@Service
public class TotpService {

    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    /** 160-bit secret — RFC 4226's recommended length — as 32 base32 characters. */
    private static final int SECRET_BYTES = 20;
    static final int PERIOD_SECONDS = 30;
    private static final int DIGITS = 6;
    /** Accept one step either side, so a phone clock 30 s adrift still works. */
    private static final int WINDOW = 1;

    private final String issuer;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public TotpService(AppProperties props) {
        this(props.name(), Clock.systemUTC());
    }

    TotpService(String issuer, Clock clock) {
        this.issuer = issuer;
        this.clock = clock;
    }

    public String generateSecret() {
        return base32Encode(Tokens.randomBytes(SECRET_BYTES));
    }

    /** The otpauth:// URI an authenticator app reads from the setup QR code. */
    public String otpauthUri(String accountEmail, String secret) {
        String label = URLEncoder.encode(issuer + ":" + accountEmail, StandardCharsets.UTF_8).replace("+", "%20");
        return "otpauth://totp/" + label
                + "?secret=" + secret
                + "&issuer=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8).replace("+", "%20")
                + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + PERIOD_SECONDS;
    }

    /**
     * The time step a code matches, or empty. Callers persist the step and refuse any
     * code at or before it — one use per code (RFC 6238 §5.2), so a code read over a
     * shoulder or phished in real time can't be replayed.
     */
    public OptionalLong matchStep(String secret, String code) {
        if (secret == null || code == null) {
            return OptionalLong.empty();
        }
        String provided = code.replaceAll("\\s", "");
        if (!provided.matches("\\d{" + DIGITS + "}")) {
            return OptionalLong.empty();
        }
        long now = clock.millis() / 1000 / PERIOD_SECONDS;
        // Check every candidate rather than returning on the first match, so the time
        // taken doesn't say which step (if any) matched.
        OptionalLong matched = OptionalLong.empty();
        for (long step = now - WINDOW; step <= now + WINDOW; step++) {
            if (MessageDigest.isEqual(codeAt(secret, step).getBytes(StandardCharsets.US_ASCII),
                    provided.getBytes(StandardCharsets.US_ASCII)) && matched.isEmpty()) {
                matched = OptionalLong.of(step);
            }
        }
        return matched;
    }

    /**
     * RFC 4226 HOTP for one counter value. Package-private for the RFC test vectors.
     *
     * <p>HMAC-SHA1 is what RFC 6238 specifies and what authenticator apps implement
     * (several ignore the {@code algorithm} parameter). HMAC's security doesn't rest on
     * SHA-1's collision resistance, which is the part that's broken.
     */
    @SuppressWarnings("java:S4790")
    String codeAt(String secret, long counter) {
        byte[] message = new byte[8];
        long value = counter;
        for (int i = 7; i >= 0; i--) {
            message[i] = (byte) (value & 0xff);
            value >>>= 8;
        }
        byte[] hash;
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(base32Decode(secret), "HmacSHA1"));
            hash = mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA1 unavailable", e);
        }
        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
        return String.format("%06d", binary % 1_000_000);
    }

    static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(BASE32.charAt((buffer >>> (bits - 5)) & 0x1f));
                bits -= 5;
            }
        }
        if (bits > 0) {
            sb.append(BASE32.charAt((buffer << (5 - bits)) & 0x1f));
        }
        return sb.toString();
    }

    static byte[] base32Decode(String s) {
        String cleaned = s.trim().replace(" ", "").replace("=", "").toUpperCase();
        int buffer = 0;
        int bits = 0;
        int index = 0;
        byte[] out = new byte[cleaned.length() * 5 / 8];
        for (char c : cleaned.toCharArray()) {
            int value = BASE32.indexOf(c);
            if (value < 0) {
                throw new IllegalArgumentException("Invalid base32 character");
            }
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                out[index++] = (byte) ((buffer >>> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out;
    }
}
