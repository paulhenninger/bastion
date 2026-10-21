package dev.bastion.mfa;

import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.common.ApiException;
import dev.bastion.email.EmailService;
import dev.bastion.security.AttemptGuard;
import dev.bastion.security.DataCipher;
import dev.bastion.security.Tokens;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.OptionalLong;

/**
 * Two-factor authentication with an authenticator app (TOTP), plus one-time recovery
 * codes for a lost device.
 *
 * <p><b>Why no emailed or SMS codes.</b> Email is this app's account-recovery channel,
 * so a code sent there is not a second factor: whoever controls the inbox can reset the
 * password <em>and</em> read the code. NIST SP 800-63B forbids email for out-of-band
 * authentication outright and restricts SMS (SIM-swap, SS7). Passkeys are the
 * phishing-resistant option and are supported separately.
 *
 * <p>Invariants:
 * <ul>
 *   <li>Enabling requires proving a code from the new secret, so a mistyped setup can't
 *       lock anyone out. The secret is held encrypted at rest (AES-GCM, bound to the
 *       account), and only promoted once proven.</li>
 *   <li>Each TOTP code works once — the matched time step is persisted and anything at or
 *       before it is refused — so a code phished in real time can't be replayed.</li>
 *   <li>Every code guess, at sign-in or re-authentication, spends a per-account budget
 *       ({@link AttemptGuard}); a fresh challenge doesn't buy fresh guesses.</li>
 *   <li>A password reset does not remove TOTP. The recovery codes, or an administrator,
 *       are the way back from a lost device.</li>
 * </ul>
 */
@Service
public class MfaService {

    static final int RECOVERY_CODE_COUNT = 10;
    static final int RECOVERY_CODE_LENGTH = 10;
    /** No 0/O, 1/I/L lookalikes — these get read off paper. 31 symbols ≈ 49.5 bits per code. */
    private static final String RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private static final int MAX_CHALLENGE_ATTEMPTS = 5;
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);

    private final UserRepository users;
    private final MfaChallengeRepository challenges;
    private final MfaRecoveryCodeRepository recoveryCodes;
    private final TotpService totp;
    private final DataCipher cipher;
    private final AttemptGuard attempts;
    private final SecurityEvents events;
    private final EmailService email;

    public MfaService(UserRepository users, MfaChallengeRepository challenges,
                      MfaRecoveryCodeRepository recoveryCodes, TotpService totp, DataCipher cipher,
                      AttemptGuard attempts, SecurityEvents events, EmailService email) {
        this.users = users;
        this.challenges = challenges;
        this.recoveryCodes = recoveryCodes;
        this.totp = totp;
        this.cipher = cipher;
        this.attempts = attempts;
        this.events = events;
        this.email = email;
    }

    /** Which second factor a code turned out to be. */
    public enum Factor { TOTP, RECOVERY_CODE }

    public record Verified(User user, Factor factor) {
    }

    public record TotpSetup(String secret, String otpauthUri) {
    }

    public record Status(boolean totpEnabled, long recoveryCodesRemaining) {
    }

    // ------------------------------------------------------------ sign-in

    /** Opens a challenge after a correct password; returns the raw token for the client. */
    @Transactional
    public String startChallenge(User user) {
        Instant now = Instant.now();
        challenges.invalidateAllForUser(user.getId(), now);
        String raw = Tokens.newOpaqueToken();
        challenges.save(new MfaChallenge(user, Tokens.sha256(raw), now.plus(CHALLENGE_TTL)));
        return raw;
    }

    /**
     * Exchanges a challenge token and a code for the user. 401 on anything wrong (the
     * client treats it as "start sign-in again" once the challenge is spent).
     * {@code noRollbackFor}: the attempt count must survive the refusal.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public Verified completeChallenge(String rawToken, String code) {
        MfaChallenge ch = challenges.findForVerification(Tokens.sha256(rawToken))
                .orElseThrow(MfaService::expired);
        Instant now = Instant.now();
        if (ch.getUsedAt() != null || ch.getExpiresAt().isBefore(now)
                || ch.getAttempts() >= MAX_CHALLENGE_ATTEMPTS) {
            throw expired();
        }
        User user = users.findByIdForUpdate(ch.getUser().getId()).orElseThrow(MfaService::expired);
        if (!user.isEnabled() || user.isLocked() || !user.isTotpEnabled()) {
            throw expired();
        }

        String budget = "mfa:" + user.getId();
        attempts.acquire(budget);
        Factor factor = verifyFactor(user, code);
        if (factor == null) {
            ch.setAttempts(ch.getAttempts() + 1);
            if (ch.getAttempts() >= MAX_CHALLENGE_ATTEMPTS) {
                ch.setUsedAt(now);
            }
            events.record(SecurityEventType.MFA_FAILED, user, "at sign-in");
            throw new ApiException(HttpStatus.UNAUTHORIZED, "That code didn't work. Check your authenticator and try again.");
        }
        attempts.clear(budget);
        ch.setUsedAt(now);
        return new Verified(user, factor);
    }

    /** Half-finished sign-ins die when the password changes: they were begun with the old one. */
    @Transactional
    public void invalidateChallenges(Long userId) {
        challenges.invalidateAllForUser(userId, Instant.now());
    }

    private static ApiException expired() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "This sign-in has expired. Please start again.");
    }

    // ------------------------------------------------------------ settings

    @Transactional(readOnly = true)
    public Status status(Long userId) {
        User user = users.findById(userId).orElseThrow();
        return new Status(user.isTotpEnabled(), user.isTotpEnabled() ? recoveryCodes.countUnused(userId) : 0);
    }

    /** Generates a fresh secret into the pending slot. Nothing is enforced until {@link #enableTotp}. */
    @Transactional
    public TotpSetup setupTotp(Long userId) {
        User user = users.findByIdForUpdate(userId).orElseThrow();
        if (user.isTotpEnabled()) {
            throw ApiException.badRequest("Two-factor authentication is already on. Turn it off first to replace it.");
        }
        String secret = totp.generateSecret();
        user.setTotpPendingSecret(cipher.encrypt(secret, pendingContext(userId)));
        return new TotpSetup(secret, totp.otpauthUri(user.getEmail(), secret));
    }

    /**
     * Confirms the pending secret with a code from it, turns TOTP on and returns fresh
     * recovery codes — the only moment they are ever visible.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public List<String> enableTotp(Long userId, String code) {
        User user = users.findByIdForUpdate(userId).orElseThrow();
        if (user.isTotpEnabled()) {
            throw ApiException.badRequest("Two-factor authentication is already on");
        }
        if (user.getTotpPendingSecret() == null) {
            throw ApiException.badRequest("Start the authenticator setup first");
        }
        String secret = cipher.decrypt(user.getTotpPendingSecret(), pendingContext(userId));
        String budget = "mfa-enable:" + userId;
        attempts.acquire(budget);
        OptionalLong step = totp.matchStep(secret, code);
        if (step.isEmpty()) {
            throw ApiException.badRequest("That code didn't match. Check the time on your phone and try again.");
        }
        attempts.clear(budget);
        user.setTotpSecret(cipher.encrypt(secret, activeContext(userId)));
        user.setTotpPendingSecret(null);
        user.setTotpLastStep(step.getAsLong());
        List<String> codes = replaceRecoveryCodes(user);
        events.record(SecurityEventType.MFA_ENABLED, user);
        email.sendSecurityNotice(user.getEmail(), "Two-factor authentication turned on",
                "Two-factor authentication with an authenticator app was turned on for your account.");
        return codes;
    }

    /** Turns TOTP off. The caller has already required a fresh re-authentication. */
    @Transactional
    public void disableTotp(Long userId) {
        User user = users.findByIdForUpdate(userId).orElseThrow();
        if (!user.isTotpEnabled()) {
            return;
        }
        clearTotp(user);
        events.record(SecurityEventType.MFA_DISABLED, user);
        email.sendSecurityNotice(user.getEmail(), "Two-factor authentication turned off",
                "Two-factor authentication was turned off for your account. Your account is now "
                        + "protected by your password alone.");
    }

    @Transactional
    public List<String> regenerateRecoveryCodes(Long userId) {
        User user = users.findByIdForUpdate(userId).orElseThrow();
        if (!user.isTotpEnabled()) {
            throw ApiException.badRequest("Turn on two-factor authentication first");
        }
        List<String> codes = replaceRecoveryCodes(user);
        events.record(SecurityEventType.RECOVERY_CODES_REGENERATED, user);
        email.sendSecurityNotice(user.getEmail(), "New recovery codes",
                "New two-factor recovery codes were generated for your account. The old ones no longer work.");
        return codes;
    }

    /** The administrator's way back for an owner who lost both device and recovery codes. */
    @Transactional
    public void adminReset(Long userId, User admin) {
        User user = users.findByIdForUpdate(userId).orElseThrow();
        clearTotp(user);
        events.record(SecurityEventType.ADMIN_RESET_MFA, user, admin, null);
        email.sendSecurityNotice(user.getEmail(), "Two-factor authentication reset",
                "An administrator turned off two-factor authentication on your account. "
                        + "Sign in and set it up again.");
    }

    // ------------------------------------------------------------ factor check

    /**
     * Checks {@code code} as a TOTP code, then as a recovery code, consuming whichever
     * matches. {@code user} must be loaded with {@link UserRepository#findByIdForUpdate}
     * in the current transaction — the TOTP replay check is read-modify-write.
     * Returns null when nothing matched; the caller owns the attempt budget.
     */
    public Factor verifyFactor(User user, String code) {
        if (code == null || code.isBlank() || !user.isTotpEnabled()) {
            return null;
        }
        String secret = cipher.decrypt(user.getTotpSecret(), activeContext(user.getId()));
        OptionalLong step = totp.matchStep(secret, code);
        if (step.isPresent()) {
            if (user.getTotpLastStep() != null && step.getAsLong() <= user.getTotpLastStep()) {
                return null; // already used — a replay
            }
            user.setTotpLastStep(step.getAsLong());
            // Re-seal under the current key if this one was written before a rotation.
            if (!cipher.isCurrent(user.getTotpSecret())) {
                user.setTotpSecret(cipher.encrypt(secret, activeContext(user.getId())));
            }
            return Factor.TOTP;
        }
        String normalized = normalizeRecoveryCode(code);
        if (normalized.length() == RECOVERY_CODE_LENGTH
                && recoveryCodes.consume(user.getId(), Tokens.sha256(normalized), Instant.now()) == 1) {
            long left = recoveryCodes.countUnused(user.getId());
            events.record(SecurityEventType.RECOVERY_CODE_USED, user, left + " left");
            email.sendSecurityNotice(user.getEmail(), "A recovery code was used",
                    "One of your two-factor recovery codes was just used to sign in. You have " + left
                            + " left. If this wasn't you, change your password and generate new codes now.");
            return Factor.RECOVERY_CODE;
        }
        return null;
    }

    // ------------------------------------------------------------ helpers

    private List<String> replaceRecoveryCodes(User user) {
        recoveryCodes.deleteAllForUser(user.getId());
        List<String> raw = new ArrayList<>(RECOVERY_CODE_COUNT);
        for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
            StringBuilder sb = new StringBuilder(RECOVERY_CODE_LENGTH + 1);
            for (int j = 0; j < RECOVERY_CODE_LENGTH; j++) {
                if (j == RECOVERY_CODE_LENGTH / 2) {
                    sb.append('-');
                }
                sb.append(RECOVERY_ALPHABET.charAt(Tokens.randomInt(RECOVERY_ALPHABET.length())));
            }
            String code = sb.toString();
            raw.add(code);
            recoveryCodes.save(new MfaRecoveryCode(user, Tokens.sha256(normalizeRecoveryCode(code))));
        }
        return raw;
    }

    private void clearTotp(User user) {
        user.setTotpSecret(null);
        user.setTotpPendingSecret(null);
        user.setTotpLastStep(null);
        users.saveAndFlush(user);
        recoveryCodes.deleteAllForUser(user.getId());
        challenges.invalidateAllForUser(user.getId(), Instant.now());
    }

    /** Uppercase, separators stripped — codes get typed from paper. */
    static String normalizeRecoveryCode(String code) {
        return code == null ? "" : code.replaceAll("[^A-Za-z0-9]", "").toUpperCase(Locale.ROOT);
    }

    private static String activeContext(Long userId) {
        return "totp:" + userId;
    }

    private static String pendingContext(Long userId) {
        return "totp-pending:" + userId;
    }
}
