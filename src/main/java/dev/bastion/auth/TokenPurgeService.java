package dev.bastion.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
public class TokenPurgeService {

    private static final Logger log = LoggerFactory.getLogger(TokenPurgeService.class);

    private final RefreshTokenRepository refreshTokens;
    private final EmailVerificationTokenRepository verificationTokens;
    private final PasswordResetTokenRepository resetTokens;

    TokenPurgeService(RefreshTokenRepository refreshTokens,
                      EmailVerificationTokenRepository verificationTokens,
                      PasswordResetTokenRepository resetTokens) {
        this.refreshTokens = refreshTokens;
        this.verificationTokens = verificationTokens;
        this.resetTokens = resetTokens;
    }

    @Transactional
    public void purgeExpired() {
        Instant now = Instant.now();
        // Revoked refresh tokens are kept 7 days so the reuse-detection breadcrumb
        // survives long enough to catch a replay; expired everything else goes now.
        int refresh = refreshTokens.purgeOld(now.minus(Duration.ofDays(7)));
        int verification = verificationTokens.purgeExpired(now);
        int reset = resetTokens.purgeExpired(now);
        log.info("Token purge: {} refresh, {} verification, {} reset rows removed",
                refresh, verification, reset);
    }
}
