package dev.bastion.mfa;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class TotpServiceTest {

    /** RFC 6238 Appendix B's SHA-1 seed, "12345678901234567890", base32-encoded. */
    private static final String RFC_SECRET =
            TotpService.base32Encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    private static TotpService at(long epochSecond) {
        return new TotpService("Test", Clock.fixed(Instant.ofEpochSecond(epochSecond), ZoneOffset.UTC));
    }

    @Test
    void matchesTheRfc6238TestVectors() {
        // RFC 6238 Appendix B (8-digit values; TOTP-6 is the last six digits).
        long[][] vectors = {
                {59L, 94287082L}, {1111111109L, 7081804L}, {1111111111L, 14050471L},
                {1234567890L, 89005924L}, {2000000000L, 69279037L}, {20000000000L, 65353130L}};
        TotpService totp = at(0);
        for (long[] v : vectors) {
            String expected = String.format("%06d", v[1] % 1_000_000);
            assertThat(totp.codeAt(RFC_SECRET, v[0] / 30)).as("T=%d", v[0]).isEqualTo(expected);
        }
    }

    @Test
    void acceptsOneStepOfClockSkewEitherSideAndNoMore() {
        long now = 1_234_567_890L;
        TotpService totp = at(now);
        long step = now / 30;
        assertThat(totp.matchStep(RFC_SECRET, totp.codeAt(RFC_SECRET, step - 1))).hasValue(step - 1);
        assertThat(totp.matchStep(RFC_SECRET, totp.codeAt(RFC_SECRET, step + 1))).hasValue(step + 1);
        assertThat(totp.matchStep(RFC_SECRET, totp.codeAt(RFC_SECRET, step + 2))).isEmpty();
        assertThat(totp.matchStep(RFC_SECRET, totp.codeAt(RFC_SECRET, step - 2))).isEmpty();
    }

    @Test
    void rejectsJunk() {
        TotpService totp = at(1_000_000L);
        assertThat(totp.matchStep(RFC_SECRET, null)).isEmpty();
        assertThat(totp.matchStep(RFC_SECRET, "12345")).isEmpty();
        assertThat(totp.matchStep(RFC_SECRET, "abcdef")).isEmpty();
        assertThat(totp.matchStep(RFC_SECRET, "1234567")).isEmpty();
    }

    @Test
    void base32RoundTripsAndSecretsAre160Bits() {
        byte[] data = "any bytes at all!!".getBytes(StandardCharsets.UTF_8);
        assertThat(TotpService.base32Decode(TotpService.base32Encode(data))).isEqualTo(data);
        assertThat(at(0).generateSecret()).hasSize(32).matches("[A-Z2-7]+");
    }

    @Test
    void otpauthUriEscapesTheLabel() {
        assertThat(at(0).otpauthUri("a+b@example.com", "ABC"))
                .isEqualTo("otpauth://totp/Test%3Aa%2Bb%40example.com?secret=ABC&issuer=Test&algorithm=SHA1&digits=6&period=30");
    }
}
