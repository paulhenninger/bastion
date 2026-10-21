package dev.bastion.session;

import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.common.ApiException;
import dev.bastion.mfa.MfaService;
import dev.bastion.security.AttemptGuard;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Step-up re-authentication ("sudo mode"). Holding a session is not the same as being
 * the account's owner: a session can be borrowed from an unlocked laptop or stolen by
 * malware. So the changes a thief would make to keep access — the email address, the
 * second factor, passkeys, account deletion, administrative actions — demand that
 * every factor the account has was proven within the last few minutes
 * ({@code app.session.reauth-minutes}).
 *
 * <p>Re-authenticating takes the password plus, when TOTP is on, a current code (or a
 * recovery code) — or a passkey assertion on its own (see PasskeyService). Guesses
 * spend a per-account budget, so a stolen access token can't grind the password here.
 */
@Service
public class ReauthService {

    private final SessionService sessions;
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final MfaService mfa;
    private final AttemptGuard attempts;
    private final SecurityEvents events;

    public ReauthService(SessionService sessions, UserRepository users, PasswordEncoder passwordEncoder,
                         MfaService mfa, AttemptGuard attempts, SecurityEvents events) {
        this.sessions = sessions;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.mfa = mfa;
        this.attempts = attempts;
        this.events = events;
    }

    /** Throws 403 {@code REAUTH_REQUIRED} unless this session re-authenticated recently. */
    public void require(AuthPrincipal me) {
        if (!sessions.isRecentlyReauthenticated(me)) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Please confirm it's you to continue",
                    ApiException.REAUTH_REQUIRED);
        }
    }

    /** Re-authenticates with password (+ code when TOTP is on) and opens the sudo window. */
    @Transactional(noRollbackFor = ApiException.class)
    public void withPassword(AuthPrincipal me, String password, String code) {
        verifyIdentity(me.userId(), password, code);
        sessions.markReauthenticated(me.sessionId());
        events.record(SecurityEventType.REAUTHENTICATED, users.getReferenceById(me.userId()), "password");
    }

    /**
     * Proves the caller knows every factor: the password and, with TOTP on, a code.
     * Used by re-authentication and by changing the password. 400 (not 401) on failure:
     * the SPA reads a 401 as an expired session and would try to refresh.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public User verifyIdentity(Long userId, String password, String code) {
        String budget = "reauth:" + userId;
        attempts.acquire(budget);
        User user = users.findByIdForUpdate(userId).orElseThrow();
        if (password == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            events.record(SecurityEventType.REAUTH_FAILED, user, "wrong password");
            throw ApiException.badRequest("Password is incorrect");
        }
        if (user.isTotpEnabled() && mfa.verifyFactor(user, code) == null) {
            events.record(SecurityEventType.REAUTH_FAILED, user, "wrong code");
            throw ApiException.badRequest(code == null || code.isBlank()
                    ? "Enter a code from your authenticator app (or a recovery code)"
                    : "That code didn't work");
        }
        attempts.clear(budget);
        return user;
    }
}
