package dev.bastion.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/** Opaque-token generation and hashing. Secrets are stored hashed, never in the clear. */
public final class Tokens {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Tokens() {
    }

    /** 256 bits of entropy, URL-safe — used for refresh, verification, reset and challenge tokens. */
    public static String newOpaqueToken() {
        return randomBase64Url(32);
    }

    /** {@code bytes} of entropy, base64url without padding. */
    public static String randomBase64Url(int bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(bytes));
    }

    public static byte[] randomBytes(int n) {
        byte[] bytes = new byte[n];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    /** A uniformly random int in [0, bound). */
    public static int randomInt(int bound) {
        return RANDOM.nextInt(bound);
    }

    /**
     * Lowercase hex SHA-256 — the only form of a token that ever touches the database.
     *
     * <p>A fast hash is right here and wrong for passwords: these tokens carry 256 bits
     * of entropy, so there is nothing to brute-force, and lookups by hash stay indexed.
     */
    public static String sha256(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Compares without leaking, through timing, how much of the value matched. */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
