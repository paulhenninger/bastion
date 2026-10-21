package dev.bastion.auth;

import dev.bastion.admin.BootstrapAdmin;
import dev.bastion.admin.SettingsService;
import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.common.ApiException;
import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailAddress;
import dev.bastion.email.EmailService;
import dev.bastion.mfa.MfaService;
import dev.bastion.passkey.PasskeyService;
import dev.bastion.security.AttemptGuard;
import dev.bastion.security.BreachedPasswords;
import dev.bastion.security.ClientInfo;
import dev.bastion.security.LoginThrottle;
import dev.bastion.security.PasswordPolicy;
import dev.bastion.security.Tokens;
import dev.bastion.session.AuthMethod;
import dev.bastion.session.SessionService;
import dev.bastion.session.SessionService.Issued;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Signup, verification, sign-in, password recovery and email-change confirmation.
 *
 * <h2>Enumeration safety</h2>
 * Nothing an anonymous caller can do reveals whether an address has an account:
 * signup, forgot-password and resend-verification reply identically (and take the same
 * time — the account-dependent work is hashed up front or done asynchronously), and a
 * failed sign-in burns one Argon2 comparison whether or not the user exists. Facts
 * about an account (unverified, locked) are only stated after the correct password.
 *
 * <h2>Account pre-hijacking</h2>
 * The classic attack: register the victim's address before they do, with a password
 * you know; when the victim later signs up and clicks the verification link, the account
 * goes live — with your password. Bastion closes it by binding passwords to signups:
 * every signup's verification token carries <em>that signup's</em> password hash, and
 * verifying requires typing the password. Verification applies the pending password the
 * person proves they know, never simply the first or the latest. An attacker can't type
 * the victim's password, and the victim's password never matches the attacker's
 * signup — whichever email they click.
 *
 * <h2>Transactions and slow work</h2>
 * Argon2 (~50 ms) and the breached-password lookup (a network call) run <em>outside</em>
 * any transaction, so a burst of sign-ins doesn't pin pooled connections while it hashes.
 */
@Service
public class AuthService {

    private static final String INVALID_LINK = "This link is invalid or has expired";
    private static final String INVALID_CREDENTIALS = "Invalid email or password";

    private final UserRepository users;
    private final EmailVerificationTokenRepository verificationTokens;
    private final PasswordResetTokenRepository resetTokens;
    private final EmailChangeTokenRepository emailChangeTokens;
    private final SessionService sessions;
    private final MfaService mfa;
    private final PasskeyService passkeys;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final BreachedPasswords breachedPasswords;
    private final LoginThrottle loginThrottle;
    private final AttemptGuard attempts;
    private final SettingsService settings;
    private final BootstrapAdmin bootstrapAdmin;
    private final RecoveryMailer recoveryMailer;
    private final EmailService email;
    private final SecurityEvents events;
    private final AppProperties props;
    private final TransactionTemplate tx;
    /** A real Argon2 hash of random material, burned on sign-ins for unknown addresses. */
    private final String timingDummyHash;

    public AuthService(UserRepository users, EmailVerificationTokenRepository verificationTokens,
                       PasswordResetTokenRepository resetTokens, EmailChangeTokenRepository emailChangeTokens,
                       SessionService sessions, MfaService mfa, PasskeyService passkeys,
                       PasswordEncoder passwordEncoder,
                       PasswordPolicy passwordPolicy, BreachedPasswords breachedPasswords,
                       LoginThrottle loginThrottle, AttemptGuard attempts, SettingsService settings,
                       BootstrapAdmin bootstrapAdmin, RecoveryMailer recoveryMailer, EmailService email,
                       SecurityEvents events, AppProperties props, PlatformTransactionManager transactionManager) {
        this.users = users;
        this.verificationTokens = verificationTokens;
        this.resetTokens = resetTokens;
        this.emailChangeTokens = emailChangeTokens;
        this.sessions = sessions;
        this.mfa = mfa;
        this.passkeys = passkeys;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.breachedPasswords = breachedPasswords;
        this.loginThrottle = loginThrottle;
        this.attempts = attempts;
        this.settings = settings;
        this.bootstrapAdmin = bootstrapAdmin;
        this.recoveryMailer = recoveryMailer;
        this.email = email;
        this.events = events;
        this.props = props;
        this.tx = new TransactionTemplate(transactionManager);
        this.timingDummyHash = passwordEncoder.encode(Tokens.newOpaqueToken());
    }

    // ------------------------------------------------------------------ signup

    public void signup(String rawEmail, String password, String name) {
        if (!settings.signupsOpen()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "New accounts can't be created right now",
                    ApiException.SIGNUPS_CLOSED);
        }
        String address = EmailAddress.normalize(rawEmail);
        // Policy and hashing first, whatever the address: the reply's timing must not
        // depend on whether an account exists.
        passwordPolicy.check(password, address);
        String hash = passwordEncoder.encode(password);
        String cleanName = name == null || name.isBlank() ? null : name.strip();

        tx.executeWithoutResult(status -> {
            Optional<User> existing = users.findByEmail(address);
            if (existing.isPresent() && existing.get().isEnabled()) {
                // Reply exactly as for a new signup; tell the real owner out of band.
                // Nothing about the existing account is touched.
                email.sendExistingAccountNotice(address);
                events.add(SecurityEventType.SIGN_UP_EXISTING_ACCOUNT, existing.get());
                return;
            }
            User user = existing.orElseGet(() -> {
                User created = new User();
                created.setEmail(address);
                // Unverified accounts can't sign in; this is only one of the candidate
                // passwords verification will accept (see the class note).
                created.setPasswordHash(hash);
                created.setName(cleanName);
                return users.save(created);
            });
            Instant now = Instant.now();
            if (verificationTokens.countPending(user.getId(), now) >= RecoveryMailer.MAX_PENDING_VERIFICATIONS) {
                return; // silently: the reply must not differ
            }
            String raw = Tokens.newOpaqueToken();
            EmailVerificationToken token = new EmailVerificationToken();
            token.setUser(user);
            token.setTokenHash(Tokens.sha256(raw));
            token.setPasswordHash(hash);
            token.setExpiresAt(now.plus(Duration.ofHours(props.verificationTokenHours())));
            verificationTokens.save(token);
            email.sendVerificationEmail(address, raw);
            events.add(SecurityEventType.SIGN_UP, user);
        });
    }

    public void resendVerification(String rawEmail) {
        recoveryMailer.resendVerification(EmailAddress.normalize(rawEmail));
    }

    /**
     * Activates the account and signs it in. The link proves the inbox; the password
     * picks which signup's password becomes the account's (see the class note).
     */
    public Issued verifyEmail(String rawToken, String password, ClientInfo client) {
        EmailVerificationToken token = verificationTokens.findByTokenHash(Tokens.sha256(rawToken))
                .filter(t -> t.getUsedAt() == null && t.getExpiresAt().isAfter(Instant.now()))
                .orElseThrow(() -> ApiException.badRequest(INVALID_LINK));
        User user = token.getUser();
        if (user.isEnabled()) {
            throw ApiException.badRequest("This address is already verified — sign in instead");
        }

        String budget = "verify:" + user.getId();
        attempts.acquire(budget);
        // Candidates: each live signup's password, plus the account's original one (so a
        // resent link still works with the password first chosen).
        List<String> candidates = new ArrayList<>();
        verificationTokens.findPendingWithPassword(user.getId(), Instant.now()).stream()
                .limit(RecoveryMailer.MAX_PENDING_VERIFICATIONS)
                .forEach(t -> candidates.add(t.getPasswordHash()));
        candidates.add(user.getPasswordHash());
        String chosen = candidates.stream()
                .filter(hash -> passwordEncoder.matches(password, hash))
                .findFirst()
                .orElseThrow(() -> ApiException.badRequest(
                        "That isn't the password you chose when signing up. If you've forgotten it, sign up again."));
        attempts.clear(budget);

        User verified = tx.execute(status -> {
            Instant now = Instant.now();
            // Every outstanding link dies; zero rows means a parallel request won.
            if (verificationTokens.consumeAllForUser(user.getId(), now) == 0) {
                throw ApiException.badRequest(INVALID_LINK);
            }
            User managed = users.findByIdForUpdate(user.getId()).orElseThrow();
            managed.setPasswordHash(chosen);
            managed.setPasswordChangedAt(now);
            managed.setEnabled(true);
            bootstrapAdmin.promoteIfEligible(managed);
            events.add(SecurityEventType.EMAIL_VERIFIED, managed);
            return managed;
        });
        return sessions.start(verified, AuthMethod.EMAIL_VERIFICATION, client);
    }

    // ------------------------------------------------------------------- login

    /** Either a session, or a challenge for the second factor. */
    public record LoginResult(Issued session, String mfaToken, boolean passwordBreached) {
    }

    public LoginResult login(String rawEmail, String password, ClientInfo client) {
        String address = EmailAddress.normalize(rawEmail);
        if (!loginThrottle.tryAcquire(address)) {
            events.addForEmail(SecurityEventType.SIGN_IN_BLOCKED, address, "too many attempts");
            throw ApiException.tooManyRequests("Too many sign-in attempts. Wait 15 minutes and try again.");
        }
        Optional<User> found = users.findByEmail(address);
        // Constant-shape verification: always one Argon2 comparison.
        String hash = found.map(User::getPasswordHash).orElse(timingDummyHash);
        boolean passwordOk = passwordEncoder.matches(password, hash);

        if (found.isEmpty() || !passwordOk) {
            if (found.isPresent()) {
                events.add(SecurityEventType.SIGN_IN_FAILED, found.get(), "wrong password");
            } else {
                events.addForEmail(SecurityEventType.SIGN_IN_FAILED, address, "unknown address");
            }
            throw new ApiException(HttpStatus.UNAUTHORIZED, INVALID_CREDENTIALS);
        }
        User user = found.get();
        // These run AFTER the password check on purpose: failing earlier would confirm
        // the account exists to someone who hasn't proven they own it.
        if (!user.isEnabled()) {
            events.add(SecurityEventType.SIGN_IN_REFUSED, user, "email not verified");
            throw new ApiException(HttpStatus.FORBIDDEN,
                    "Email address not verified. Check your inbox or request a new link.",
                    ApiException.EMAIL_NOT_VERIFIED);
        }
        if (user.isLocked()) {
            events.add(SecurityEventType.SIGN_IN_REFUSED, user, "account locked");
            throw new ApiException(HttpStatus.FORBIDDEN, "This account has been locked. Contact support.",
                    ApiException.ACCOUNT_LOCKED);
        }
        if (passwordEncoder.upgradeEncoding(user.getPasswordHash())) {
            // Transparent migration (BCrypt → Argon2id): we hold the plaintext only now.
            String upgraded = passwordEncoder.encode(password);
            tx.executeWithoutResult(s -> users.findById(user.getId()).ifPresent(u -> u.setPasswordHash(upgraded)));
        }
        boolean breached = breachedPasswords.isBreached(password);

        if (user.isTotpEnabled()) {
            // Not a completed sign-in: the attempt budget stands until the code is right.
            return new LoginResult(null, mfa.startChallenge(user), breached);
        }
        loginThrottle.recordSuccess(address);
        return new LoginResult(sessions.start(user, AuthMethod.PASSWORD, client), null, breached);
    }

    public Issued completeMfa(String mfaToken, String code, ClientInfo client) {
        MfaService.Verified verified = mfa.completeChallenge(mfaToken, code);
        loginThrottle.recordSuccess(verified.user().getEmail());
        AuthMethod method = verified.factor() == MfaService.Factor.TOTP
                ? AuthMethod.PASSWORD_TOTP : AuthMethod.PASSWORD_RECOVERY_CODE;
        return sessions.start(verified.user(), method, client);
    }

    /**
     * Passwordless sign-in. A user-verified passkey is possession plus biometric/PIN —
     * two factors in one gesture — so it neither asks for the password nor for TOTP.
     */
    public Issued passkeyLogin(PasskeyService.Assertion assertion, ClientInfo client) {
        User user = passkeys.authenticate(assertion);
        loginThrottle.recordSuccess(user.getEmail());
        return sessions.start(user, AuthMethod.PASSKEY, client);
    }

    public Optional<Issued> refresh(String rawRefreshToken) {
        return sessions.rotate(rawRefreshToken);
    }

    public void logout(String rawRefreshToken) {
        sessions.signOut(rawRefreshToken);
    }

    // -------------------------------------------------------- password recovery

    public void forgotPassword(String rawEmail) {
        String address = EmailAddress.normalize(rawEmail);
        // Recorded whether or not the address has an account: a run of these across
        // many addresses is itself the thing worth seeing.
        events.addForEmail(SecurityEventType.PASSWORD_RESET_REQUESTED, address, null);
        // Captured here: the mailer runs on another thread, where the request is gone.
        recoveryMailer.sendPasswordReset(address, ClientInfo.current());
    }

    /**
     * Sets a new password from an emailed link. Ends every session and half-finished
     * sign-in (whoever reset it owns the account now). Deliberately does NOT sign in and
     * does NOT remove two-factor: an inbox alone must not get past a second factor.
     */
    public void resetPassword(String rawToken, String newPassword) {
        PasswordResetToken token = resetTokens.findByTokenHash(Tokens.sha256(rawToken))
                .filter(t -> t.getUsedAt() == null && t.getExpiresAt().isAfter(Instant.now()))
                .orElseThrow(() -> ApiException.badRequest(INVALID_LINK));
        Long userId = token.getUser().getId();
        passwordPolicy.check(newPassword, token.getUser().getEmail());
        String hash = passwordEncoder.encode(newPassword);

        User user = tx.execute(status -> {
            Instant now = Instant.now();
            if (resetTokens.consume(token.getId(), now) == 0) {
                throw ApiException.badRequest(INVALID_LINK);
            }
            resetTokens.consumeAllForUser(userId, now);
            User managed = users.findByIdForUpdate(userId).orElseThrow();
            managed.setPasswordHash(hash);
            managed.setPasswordChangedAt(now);
            return managed;
        });
        sessions.revokeAll(userId);
        mfa.invalidateChallenges(userId);
        events.add(SecurityEventType.PASSWORD_RESET, user);
        email.sendSecurityNotice(user.getEmail(), "Your password was reset",
                "The password for your account was just reset using a link sent to this address, "
                        + "and every device was signed out.");
    }

    // ------------------------------------------------------------ email change

    /** Completes a change requested from account settings: the link went to the new address. */
    public void confirmEmailChange(String rawToken) {
        EmailChangeToken token = emailChangeTokens.findByTokenHash(Tokens.sha256(rawToken))
                .filter(t -> t.getUsedAt() == null && t.getExpiresAt().isAfter(Instant.now()))
                .orElseThrow(() -> ApiException.badRequest(INVALID_LINK));
        Long userId = token.getUser().getId();
        String newAddress = token.getNewEmail();

        String previous = tx.execute(status -> {
            Instant now = Instant.now();
            if (emailChangeTokens.consume(token.getId(), now) == 0) {
                throw ApiException.badRequest(INVALID_LINK);
            }
            // Claimed by someone else since it was requested? Whoever clicked controls
            // this inbox, so saying it's taken reveals nothing they couldn't learn.
            if (users.existsByEmail(newAddress)) {
                throw new ApiException(HttpStatus.CONFLICT, "That address now belongs to another account");
            }
            emailChangeTokens.consumeAllForUser(userId, now);
            User managed = users.findByIdForUpdate(userId).orElseThrow();
            String old = managed.getEmail();
            managed.setEmail(newAddress);
            events.add(SecurityEventType.EMAIL_CHANGED, managed, "from " + old);
            return old;
        });
        // The sign-in identifier changed: every session signs in again with it.
        sessions.revokeAll(userId);
        email.sendSecurityNotice(previous, "Your email address was changed",
                "The email address on your account was changed to " + newAddress
                        + ". Messages about your account now go there.");
        email.sendSecurityNotice(newAddress, "Your email address was changed",
                "This is now the email address of your account. Please sign in again.");
    }
}
