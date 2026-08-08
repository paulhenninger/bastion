package dev.bastion;

import dev.bastion.auth.RefreshToken;
import dev.bastion.auth.RefreshTokenRepository;
import dev.bastion.auth.RefreshTokenService;
import dev.bastion.security.Tokens;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@org.springframework.transaction.annotation.Transactional
class RefreshTokenServiceTest {

    @Autowired
    private RefreshTokenService service;
    @Autowired
    private RefreshTokenRepository repository;
    @Autowired
    private UserRepository users;

    private User user;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
        users.deleteAll();
        user = new User();
        user.setEmail("athlete@example.com");
        user.setPasswordHash("x");
        user.setEnabled(true);
        user = users.save(user);
    }

    @Test
    void rotationConsumesTheOldTokenAndIssuesANewOne() {
        String first = service.issue(user);

        var rotation = service.rotate(first);
        assertThat(rotation).isPresent();
        assertThat(rotation.get().newRawToken()).isNotEqualTo(first);

        // The consumed token no longer rotates (within the grace window: no nuke).
        assertThat(service.rotate(first)).isEmpty();
        // But the replacement still works — the benign two-tab race didn't kill the session.
        assertThat(service.rotate(rotation.get().newRawToken())).isPresent();
    }

    @Test
    void replayLongAfterRotationRevokesEverySession() {
        String stolen = service.issue(user);
        var rotation = service.rotate(stolen);
        assertThat(rotation).isPresent();

        // Simulate time passing: backdate the revocation beyond the grace window.
        RefreshToken consumed = repository.findByTokenHash(Tokens.sha256(stolen)).orElseThrow();
        consumed.setRevokedAt(Instant.now().minus(RefreshTokenService.REUSE_GRACE)
                .minus(Duration.ofSeconds(5)));
        repository.save(consumed);

        // The thief replays the stolen (consumed) token…
        assertThat(service.rotate(stolen)).isEmpty();
        // …and the legitimate session dies with it: every token is revoked.
        assertThat(service.rotate(rotation.get().newRawToken())).isEmpty();
    }

    @Test
    void expiredTokensDoNotRotate() {
        String raw = service.issue(user);
        RefreshToken token = repository.findByTokenHash(Tokens.sha256(raw)).orElseThrow();
        token.setExpiresAt(Instant.now().minus(Duration.ofMinutes(1)));
        repository.save(token);

        assertThat(service.rotate(raw)).isEmpty();
    }

    @Test
    void unknownTokensDoNotRotate() {
        assertThat(service.rotate("never-issued")).isEmpty();
    }
}
