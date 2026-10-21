package dev.bastion.auth;

import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailService;
import dev.bastion.security.ClientInfo;
import dev.bastion.security.Tokens;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

/**
 * The account lookups behind forgot-password and resend-verification, run <b>off the
 * request thread</b>.
 *
 * <p>Those endpoints reply with the same sentence whether or not the address has an
 * account, so the <em>time</em> must be the same too. Done inline, a registered address
 * costs a token insert and a mail hand-off that an unknown one doesn't — a measurable
 * difference that turns the generic reply back into an enumeration oracle. Here the
 * request thread does identical work in both cases (queue a task) and this does the
 * rest unseen.
 */
@Service
class RecoveryMailer {

    /** More than this many live links for one account is abuse, not forgetfulness. */
    static final int MAX_PENDING_VERIFICATIONS = 5;

    private final UserRepository users;
    private final PasswordResetTokenRepository resetTokens;
    private final EmailVerificationTokenRepository verificationTokens;
    private final EmailService email;
    private final AppProperties props;

    RecoveryMailer(UserRepository users, PasswordResetTokenRepository resetTokens,
                   EmailVerificationTokenRepository verificationTokens, EmailService email,
                   AppProperties props) {
        this.users = users;
        this.resetTokens = resetTokens;
        this.verificationTokens = verificationTokens;
        this.email = email;
        this.props = props;
    }

    @Async
    @Transactional
    public void sendPasswordReset(String normalizedEmail, ClientInfo requestedBy) {
        users.findByEmail(normalizedEmail)
                .filter(u -> u.isEnabled() && !u.isLocked())
                .ifPresent(user -> {
                    Instant now = Instant.now();
                    // Only the newest link works: an older one sitting in an inbox is a liability.
                    resetTokens.consumeAllForUser(user.getId(), now);
                    String raw = Tokens.newOpaqueToken();
                    PasswordResetToken token = new PasswordResetToken();
                    token.setUser(user);
                    token.setTokenHash(Tokens.sha256(raw));
                    token.setExpiresAt(now.plus(Duration.ofMinutes(props.resetTokenMinutes())));
                    resetTokens.save(token);
                    email.sendPasswordResetEmail(user.getEmail(), raw, requestedBy);
                });
    }

    @Async
    @Transactional
    public void resendVerification(String normalizedEmail) {
        users.findByEmail(normalizedEmail)
                .filter(u -> !u.isEnabled())
                .ifPresent(this::sendVerificationLink);
    }

    /** A link that proves the inbox; the password is checked against the signup(s) at verification. */
    private void sendVerificationLink(User user) {
        Instant now = Instant.now();
        if (verificationTokens.countPending(user.getId(), now) >= MAX_PENDING_VERIFICATIONS) {
            return;
        }
        String raw = Tokens.newOpaqueToken();
        EmailVerificationToken token = new EmailVerificationToken();
        token.setUser(user);
        token.setTokenHash(Tokens.sha256(raw));
        token.setExpiresAt(now.plus(Duration.ofHours(props.verificationTokenHours())));
        verificationTokens.save(token);
        email.sendVerificationEmail(user.getEmail(), raw);
    }
}
