package dev.bastion.security;

import dev.bastion.config.AppProperties;
import org.springframework.stereotype.Component;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * AES-256-GCM encryption for the few secrets the server must read back — today,
 * TOTP shared secrets. Hashing can't work for those: verifying a code needs the
 * secret itself. Encrypting them means a stolen backup or a read-only SQL injection
 * yields ciphertext, not the second factor of every account.
 *
 * <p>Format: {@code v1:<key id>:<base64(iv || ciphertext || tag)>}. The key id lets
 * old values stay readable through a rotation: put the new key in
 * {@code DATA_ENCRYPTION_KEY}, the old one in {@code DATA_ENCRYPTION_PREVIOUS_KEYS};
 * values re-encrypt under the new key the next time they're written.
 *
 * <p>Each value is bound to its purpose with GCM associated data (e.g.
 * {@code "totp:<userId>"}), so a ciphertext copied into another row or column fails
 * to decrypt rather than quietly becoming someone else's secret.
 *
 * <p>Required at startup, like the JWT secret: a missing or short key fails fast.
 */
@Component
public class DataCipher {

    private static final String PREFIX = "v1:";
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final String currentId;
    private final Map<String, SecretKey> keys = new LinkedHashMap<>();

    public DataCipher(AppProperties props) {
        String key = props.encryption().key();
        if (key == null || key.isBlank()) {
            throw new IllegalStateException(
                    "DATA_ENCRYPTION_KEY is required. Generate one with: openssl rand -base64 32");
        }
        this.currentId = add(key, "DATA_ENCRYPTION_KEY");
        for (String previous : props.encryption().previousKeys().split(",")) {
            if (!previous.isBlank()) {
                add(previous, "DATA_ENCRYPTION_PREVIOUS_KEYS");
            }
        }
    }

    private String add(String base64, String name) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(base64.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(name + " is not valid base64", e);
        }
        if (bytes.length != 32) {
            throw new IllegalStateException(name + " must decode to exactly 32 bytes (256 bits)");
        }
        try {
            // An identifier, not a secret: enough of a digest to tell keys apart.
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            String id = HexFormat.of().formatHex(digest, 0, 4);
            keys.put(id, new SecretKeySpec(bytes, "AES"));
            return id;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Encrypts {@code plaintext}, bound to {@code context} (e.g. "totp:42"). */
    public String encrypt(String plaintext, String context) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] iv = Tokens.randomBytes(IV_BYTES);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, keys.get(currentId), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + sealed.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(sealed, 0, out, iv.length, sealed.length);
            return PREFIX + currentId + ":" + Base64.getEncoder().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /**
     * Decrypts a value written by {@link #encrypt}. Loud on any failure — an unknown
     * key, a tampered value, the wrong context — because returning something else
     * would let it be saved back over the real secret.
     */
    public String decrypt(String stored, String context) {
        if (stored == null) {
            return null;
        }
        String[] parts = stored.split(":", 3);
        if (parts.length != 3 || !PREFIX.equals(parts[0] + ":")) {
            throw new IllegalStateException("Stored value is not in the expected encrypted format");
        }
        SecretKey key = keys.get(parts[1]);
        if (key == null) {
            throw new IllegalStateException("Stored value was encrypted under key " + parts[1]
                    + ", which is not configured (DATA_ENCRYPTION_KEY / DATA_ENCRYPTION_PREVIOUS_KEYS)");
        }
        try {
            byte[] blob = Base64.getDecoder().decode(parts[2]);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, blob, 0, IV_BYTES));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(blob, IV_BYTES, blob.length - IV_BYTES), StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new IllegalStateException("Stored value failed authentication (tampered or moved)", e);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Stored value could not be decrypted", e);
        }
    }

    /** Whether a stored value is sealed under the current key (false = re-encrypt on next write). */
    public boolean isCurrent(String stored) {
        return stored != null && stored.startsWith(PREFIX + currentId + ":");
    }
}
