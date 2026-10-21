package dev.bastion.security;

import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailAddress;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The building blocks, without Spring. */
class SecurityPrimitivesTest {

    private static final String KEY_A = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private static final String KEY_B = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";
    private static final String JWT_SECRET = "dGVzdC1zZWNyZXQtbXVzdC1iZS0yNTYtYml0cy1sb25nISE=";

    static AppProperties props(Map<String, String> overrides) {
        Map<String, String> values = new HashMap<>();
        values.put("app.jwt-secret", JWT_SECRET);
        values.put("app.encryption.key", KEY_A);
        values.putAll(overrides);
        return new Binder(new MapConfigurationPropertySource(values)).bind("app", AppProperties.class).get();
    }

    // ------------------------------------------------------------ DataCipher

    @Test
    void cipherRoundTripsAndNeverRepeatsCiphertext() {
        DataCipher cipher = new DataCipher(props(Map.of()));
        String a = cipher.encrypt("JBSWY3DPEHPK3PXP", "totp:1");
        String b = cipher.encrypt("JBSWY3DPEHPK3PXP", "totp:1");
        assertThat(a).isNotEqualTo(b).startsWith("v1:");
        assertThat(cipher.decrypt(a, "totp:1")).isEqualTo("JBSWY3DPEHPK3PXP");
    }

    @Test
    void cipherRefusesTamperingAndValuesMovedToAnotherRow() {
        DataCipher cipher = new DataCipher(props(Map.of()));
        String sealed = cipher.encrypt("secret", "totp:1");
        assertThatThrownBy(() -> cipher.decrypt(sealed, "totp:2")).isInstanceOf(IllegalStateException.class);
        int split = sealed.lastIndexOf(':') + 1;
        byte[] blob = java.util.Base64.getDecoder().decode(sealed.substring(split));
        blob[14] ^= 0x01; // one bit of ciphertext (past the 12-byte IV)
        String flipped = sealed.substring(0, split) + java.util.Base64.getEncoder().encodeToString(blob);
        assertThatThrownBy(() -> cipher.decrypt(flipped, "totp:1")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void cipherKeyRotationKeepsOldValuesReadable() {
        String old = new DataCipher(props(Map.of())).encrypt("secret", "ctx");
        DataCipher rotated = new DataCipher(props(Map.of("app.encryption.key", KEY_B,
                "app.encryption.previous-keys", KEY_A)));
        assertThat(rotated.decrypt(old, "ctx")).isEqualTo("secret");
        assertThat(rotated.isCurrent(old)).isFalse();
        assertThat(rotated.isCurrent(rotated.encrypt("secret", "ctx"))).isTrue();
        assertThatThrownBy(() -> new DataCipher(props(Map.of("app.encryption.key", KEY_B))).decrypt(old, "ctx"))
                .hasMessageContaining("not configured");
    }

    @Test
    void cipherRefusesToStartWithoutAProperKey() {
        assertThatThrownBy(() -> new DataCipher(props(Map.of("app.encryption.key", ""))))
                .hasMessageContaining("DATA_ENCRYPTION_KEY is required");
        assertThatThrownBy(() -> new DataCipher(props(Map.of("app.encryption.key", "c2hvcnQ="))))
                .hasMessageContaining("32 bytes");
    }

    // ------------------------------------------------------------ JwtService

    @Test
    void jwtRoundTripsAndRejectsForeignKeysAndWeakSecrets() {
        JwtService jwt = new JwtService(props(Map.of()));
        String token = jwt.issueAccessToken(42L, "session-id");
        assertThat(jwt.validate(token)).contains(new JwtService.AccessClaims(42L, "session-id"));
        assertThat(jwt.validate("not.a.token")).isEmpty();

        JwtService other = new JwtService(props(Map.of("app.jwt-secret", KEY_B)));
        assertThat(jwt.validate(other.issueAccessToken(42L, "s"))).isEmpty();

        assertThatThrownBy(() -> new JwtService(props(Map.of("app.jwt-secret", ""))))
                .hasMessageContaining("JWT_SECRET is required");
        assertThatThrownBy(() -> new JwtService(props(Map.of("app.jwt-secret", "c2hvcnQ="))))
                .hasMessageContaining("256 bits");
    }

    @Test
    void jwtWithTheRightKeyButWrongAudienceIsRejected() {
        byte[] key = java.util.Base64.getDecoder().decode(JWT_SECRET);
        String foreign = io.jsonwebtoken.Jwts.builder().issuer("bastion").audience().add("some-other-api").and()
                .subject("42").claim("sid", "s").expiration(java.util.Date.from(Instant.now().plusSeconds(60)))
                .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(key)).compact();
        assertThat(new JwtService(props(Map.of())).validate(foreign)).isEmpty();
    }

    // ---------------------------------------------------------- WindowCounter

    @Test
    void windowCounterResetsAfterItsWindowAndStaysBounded() {
        AtomicLong now = new AtomicLong(0);
        Clock clock = new Clock() {
            public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
            public Clock withZone(java.time.ZoneId zone) { return this; }
            public Instant instant() { return Instant.ofEpochMilli(now.get()); }
        };
        WindowCounter counter = new WindowCounter(Duration.ofMinutes(1), 100, clock);
        assertThat(counter.increment("a")).isEqualTo(1);
        assertThat(counter.increment("a")).isEqualTo(2);
        now.addAndGet(60_000);
        assertThat(counter.increment("a")).isEqualTo(1);

        for (int i = 0; i < 1_000; i++) {
            counter.increment("spray-" + i); // all fresh: pruning expired ones alone frees nothing
        }
        assertThat(counter.size()).isLessThanOrEqualTo(100);
    }

    // ----------------------------------------------------- BreachedPasswords

    @Test
    void breachCheckMatchesSuffixesIgnoresPaddingAndFailsOpen() {
        String hash = BreachedPasswords.sha1Hex("password1");
        String suffix = hash.substring(5);
        assertThat(new BreachedPasswords(true, prefix -> "0000:1\r\n" + suffix + ":42").isBreached("password1")).isTrue();
        assertThat(new BreachedPasswords(true, prefix -> suffix + ":0").isBreached("password1")).isFalse();
        assertThat(new BreachedPasswords(true, prefix -> { throw new IllegalStateException("down"); })
                .isBreached("password1")).isFalse();
        // Only the 5-character prefix ever leaves the server.
        new BreachedPasswords(true, prefix -> {
            assertThat(prefix).hasSize(5);
            return "";
        }).isBreached("anything");
    }

    // ---------------------------------------------------------- EmailAddress

    @Test
    void emailSyntaxIsStrictButAcceptsRealAddresses() {
        assertThat(EmailAddress.problem("first.last+tag@sub.example.co.uk")).isNull();
        assertThat(EmailAddress.problem("user@xn--80ak6aa92e.xn--p1ai")).isNull(); // punycode TLD
        assertThat(EmailAddress.problem("a@b")).contains("top-level domain");
        assertThat(EmailAddress.problem("user@localhost")).isNotNull();
        assertThat(EmailAddress.problem("user@[127.0.0.1]")).isNotNull();
        assertThat(EmailAddress.problem("\"quoted\"@example.com")).isNotNull();
        assertThat(EmailAddress.problem("two@@example.com")).isNotNull();
        assertThat(EmailAddress.problem("dot..dot@example.com")).isNotNull();
        assertThat(EmailAddress.problem("a@" + "x".repeat(250) + ".com")).isNotNull();
        assertThat(EmailAddress.problem("line\nbreak@example.com")).isNotNull();
    }
}
