package dev.bastion.auth;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/** Deletes expired one-time tokens (verification, reset, email change). Run by PurgeJob. */
@Service
public class TokenPurge {

    private final EmailVerificationTokenRepository verificationTokens;
    private final PasswordResetTokenRepository resetTokens;
    private final EmailChangeTokenRepository emailChangeTokens;

    TokenPurge(EmailVerificationTokenRepository verificationTokens, PasswordResetTokenRepository resetTokens,
               EmailChangeTokenRepository emailChangeTokens) {
        this.verificationTokens = verificationTokens;
        this.resetTokens = resetTokens;
        this.emailChangeTokens = emailChangeTokens;
    }

    @Transactional
    public int purgeExpired() {
        Instant now = Instant.now();
        return verificationTokens.purgeExpired(now) + resetTokens.purgeExpired(now)
                + emailChangeTokens.purgeExpired(now);
    }
}
