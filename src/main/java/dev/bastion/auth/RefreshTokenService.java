package dev.bastion.auth;

import dev.bastion.config.AppProperties;
import dev.bastion.security.Tokens;
import dev.bastion.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Rotating refresh tokens with theft detection.
 *
 * <p>Every refresh consumes the presented token and issues a replacement. Replaying a
 * consumed token more than {@link #REUSE_GRACE} after rotation is treated as theft and
 * revokes every session the user has; inside the grace window it's the benign two-tab
 * race (two tabs refreshing at once) and is rejected without the nuke.
 */
@Service
public class RefreshTokenService {

    /** Replay within this window after rotation = a concurrency race, not an attack. */
    public static final Duration REUSE_GRACE = Duration.ofSeconds(60);

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository repository;
    private final Duration refreshTtl;

    public RefreshTokenService(RefreshTokenRepository repository, AppProperties props) {
        this.repository = repository;
        this.refreshTtl = Duration.ofDays(props.refreshTokenDays());
    }

    /** Mints a fresh token for a new session. Returns the raw value (stored only as a hash). */
    @Transactional
    public String issue(User user) {
        String raw = Tokens.newOpaqueToken();
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setTokenHash(Tokens.sha256(raw));
        token.setExpiresAt(Instant.now().plus(refreshTtl));
        repository.save(token);
        return raw;
    }

    /**
     * Consumes the presented token and returns a replacement, or empty when the
     * presented token is unknown, expired, or revoked (with the theft rule applied).
     */
    @Transactional
    public Optional<Rotation> rotate(String rawToken) {
        Optional<RefreshToken> found = repository.findByTokenHash(Tokens.sha256(rawToken));
        if (found.isEmpty()) {
            return Optional.empty();
        }
        RefreshToken current = found.get();
        Instant now = Instant.now();

        if (current.getRevokedAt() != null) {
            if (current.getRevokedAt().plus(REUSE_GRACE).isBefore(now)) {
                // A consumed token replayed well after rotation: someone else has it.
                log.warn("Refresh token reuse detected for user {} — revoking all sessions",
                        current.getUser().getId());
                repository.revokeAllForUser(current.getUser().getId(), now);
            }
            return Optional.empty();
        }
        if (current.getExpiresAt().isBefore(now)) {
            return Optional.empty();
        }

        String raw = Tokens.newOpaqueToken();
        RefreshToken replacement = new RefreshToken();
        replacement.setUser(current.getUser());
        replacement.setTokenHash(Tokens.sha256(raw));
        replacement.setExpiresAt(now.plus(refreshTtl));
        repository.save(replacement);

        current.setRevokedAt(now);
        current.setReplacedByHash(replacement.getTokenHash());
        repository.save(current);

        return Optional.of(new Rotation(current.getUser(), raw));
    }

    /** Revokes just the presented token (logout of this session). */
    @Transactional
    public void revoke(String rawToken) {
        repository.findByTokenHash(Tokens.sha256(rawToken)).ifPresent(token -> {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(Instant.now());
                repository.save(token);
            }
        });
    }

    /** Revokes every session — password change/reset, admin lock, account deletion. */
    @Transactional
    public void revokeAllForUser(Long userId) {
        repository.revokeAllForUser(userId, Instant.now());
    }

    public record Rotation(User user, String newRawToken) {
    }
}
