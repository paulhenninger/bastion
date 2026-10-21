package dev.bastion.session;

import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailService;
import dev.bastion.security.ClientInfo;
import dev.bastion.security.JwtService;
import dev.bastion.security.Tokens;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Sessions: one row per sign-in, with rotating refresh tokens underneath.
 *
 * <ul>
 *   <li><b>Rotation with theft detection.</b> Every refresh consumes the presented token
 *       and issues a replacement. Replaying a consumed token more than {@link #REUSE_GRACE}
 *       after rotation means two parties hold it — every session the user has is
 *       revoked and the owner is emailed. Inside the grace window it's the benign
 *       two-tab race and is merely refused (the SPA retries with the new cookie).</li>
 *   <li><b>Rotation is serialised</b> with a row lock, so one token can never fork into
 *       two live sessions however the requests interleave.</li>
 *   <li><b>Idle and absolute lifetimes.</b> A session ends after {@code idle-days}
 *       without a refresh, and {@code max-days} after sign-in however active.</li>
 *   <li><b>Revocation is immediate.</b> The access token names its session; the auth
 *       filter checks the row on every request ({@link #resolve}).</li>
 * </ul>
 */
@Service
public class SessionService {

    /** Replay within this window after rotation = a concurrency race, not an attack. */
    public static final Duration REUSE_GRACE = Duration.ofSeconds(60);
    /** How far back "have we seen this device before?" looks for new-sign-in alerts. */
    private static final Duration DEVICE_MEMORY = Duration.ofDays(90);

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final UserSessionRepository sessions;
    private final RefreshTokenRepository refreshTokens;
    private final UserRepository users;
    private final JwtService jwt;
    private final SecurityEvents events;
    private final EmailService email;
    private final Duration idleTtl;
    private final Duration maxTtl;
    private final Duration reauthWindow;
    private final boolean newSignInAlerts;

    public SessionService(UserSessionRepository sessions, RefreshTokenRepository refreshTokens,
                          UserRepository users, JwtService jwt, SecurityEvents events,
                          EmailService email, AppProperties props) {
        this.sessions = sessions;
        this.refreshTokens = refreshTokens;
        this.users = users;
        this.jwt = jwt;
        this.events = events;
        this.email = email;
        this.idleTtl = Duration.ofDays(props.session().idleDays());
        this.maxTtl = Duration.ofDays(props.session().maxDays());
        this.reauthWindow = Duration.ofMinutes(props.session().reauthMinutes());
        this.newSignInAlerts = props.session().newSignInAlerts();
    }

    /** A freshly authenticated session: short-lived JWT + the raw refresh token for the cookie. */
    public record Issued(String accessToken, String refreshToken, UserSession session, User user) {
    }

    // -------------------------------------------------------------- lifecycle

    /** Starts a session after a completed sign-in. The caller has already proven every factor. */
    @Transactional
    public Issued start(User user, AuthMethod method, ClientInfo client) {
        Instant now = Instant.now();
        UserSession session = new UserSession();
        session.setPublicId(Tokens.randomBase64Url(24));
        session.setUser(user);
        session.setAuthMethod(method);
        session.setStrongAuth(method.isStrong());
        session.setIp(client.ip());
        session.setUserAgent(client.userAgent());
        session.setCreatedAt(now);
        session.setLastSeenAt(now);
        session.setExpiresAt(now.plus(maxTtl));
        // Having just proven every factor counts as a fresh re-authentication.
        session.setReauthAt(now);
        sessions.save(session);

        User managed = users.findById(user.getId()).orElseThrow();
        Instant previousSignIn = managed.getLastLoginAt();
        managed.setLastLoginAt(now);

        String raw = mintRefreshToken(session, managed, now);
        events.add(SecurityEventType.SIGN_IN, managed, method.name());
        alertIfNewDevice(managed, session, previousSignIn, now);
        return new Issued(jwt.issueAccessToken(managed.getId(), session.getPublicId()), raw, session, managed);
    }

    /**
     * Consumes the presented refresh token and returns a replacement, or empty when it
     * is unknown, expired, revoked, or its session/account is no longer allowed in.
     * Never throws for a bad token, so the reuse-detection revocation always commits.
     */
    @Transactional
    public Optional<Issued> rotate(String rawToken) {
        Optional<RefreshToken> found = refreshTokens.findForRotation(Tokens.sha256(rawToken));
        if (found.isEmpty()) {
            return Optional.empty();
        }
        RefreshToken current = found.get();
        UserSession session = current.getSession();
        User user = current.getUser();
        Instant now = Instant.now();

        if (current.getRevokedAt() != null) {
            if (current.getRevokedAt().plus(REUSE_GRACE).isBefore(now) && session.getRevokedAt() == null) {
                // A consumed token replayed well after rotation: two parties hold this
                // session. We can't tell which is the owner, so everyone signs in again.
                log.warn("Refresh token reuse detected for user {} — revoking all sessions", user.getId());
                revokeEverything(user.getId(), now);
                events.add(SecurityEventType.REFRESH_TOKEN_REUSE, user);
                email.sendSecurityNotice(user.getEmail(), "Suspicious session activity",
                        "A sign-in token for your account was used twice, which can mean it was copied. "
                                + "As a precaution every device has been signed out. If you don't recognise "
                                + "recent activity, change your password.");
            }
            return Optional.empty();
        }
        if (current.getExpiresAt().isBefore(now) || !session.isActive(now)
                || !user.isEnabled() || user.isLocked()) {
            return Optional.empty();
        }

        String raw = mintRefreshToken(session, user, now);
        current.setRevokedAt(now);
        current.setReplacedByHash(Tokens.sha256(raw));
        session.setLastSeenAt(now);
        return Optional.of(new Issued(jwt.issueAccessToken(user.getId(), session.getPublicId()), raw, session, user));
    }

    /** Sign-out of the session the presented token belongs to. */
    @Transactional
    public void signOut(String rawToken) {
        refreshTokens.findByTokenHash(Tokens.sha256(rawToken)).ifPresent(token -> {
            UserSession session = token.getSession();
            if (session.getRevokedAt() == null) {
                revoke(session, Instant.now());
                events.add(SecurityEventType.SIGN_OUT, token.getUser());
            }
        });
    }

    /** Ends one of {@code userId}'s sessions by its public id. */
    @Transactional
    public boolean revoke(Long userId, String publicId) {
        return sessions.findByPublicIdAndUserId(publicId, userId)
                .filter(s -> s.getRevokedAt() == null)
                .map(s -> {
                    revoke(s, Instant.now());
                    return true;
                })
                .orElse(false);
    }

    /** Every session — password reset, admin lock, account deletion, token theft. */
    @Transactional
    public void revokeAll(Long userId) {
        revokeEverything(userId, Instant.now());
    }

    /** Every session but the caller's — password change, "sign out other devices". */
    @Transactional
    public int revokeOthers(Long userId, Long keepSessionId) {
        Instant now = Instant.now();
        int ended = sessions.revokeOthers(userId, keepSessionId, now);
        refreshTokens.revokeAllForUserExceptSession(userId, keepSessionId, now);
        return ended;
    }

    // ------------------------------------------------------------ per request

    /**
     * The session an access token names, if it is still good: not revoked, not past
     * its absolute expiry, belonging to that user, whose account is verified and
     * unlocked. One indexed query per request.
     */
    @Transactional(readOnly = true)
    public Optional<AuthPrincipal> resolve(Long userId, String publicId) {
        Instant now = Instant.now();
        return sessions.findByPublicIdWithUser(publicId)
                .filter(s -> s.getUser().getId().equals(userId))
                .filter(s -> s.isActive(now))
                .filter(s -> s.getUser().isEnabled() && !s.getUser().isLocked())
                .map(s -> new AuthPrincipal(userId, s.getUser().getEmail(), s.getUser().getRole(),
                        s.getId(), s.getPublicId(), s.isStrongAuth(), s.getReauthAt()));
    }

    // ------------------------------------------------------------ step-up

    public boolean isRecentlyReauthenticated(AuthPrincipal me) {
        return me.reauthAt() != null && me.reauthAt().plus(reauthWindow).isAfter(Instant.now());
    }

    public Duration reauthWindow() {
        return reauthWindow;
    }

    @Transactional
    public void markReauthenticated(Long sessionId) {
        sessions.findById(sessionId).ifPresent(s -> s.setReauthAt(Instant.now()));
    }

    /** A second factor was just proven inside this session (by enrolling one). */
    @Transactional
    public void markStrong(Long sessionId) {
        sessions.findById(sessionId).ifPresent(s -> {
            s.setStrongAuth(true);
            s.setReauthAt(Instant.now());
        });
    }

    @Transactional(readOnly = true)
    public List<UserSession> active(Long userId) {
        return sessions.findActive(userId, Instant.now());
    }

    @Transactional
    public int purgeOld() {
        Instant cutoff = Instant.now().minus(Duration.ofDays(7));
        // Revoked refresh tokens are kept 7 days so the reuse breadcrumb survives
        // long enough to catch a replay; sessions likewise.
        int tokens = refreshTokens.purgeOld(cutoff);
        int ended = sessions.purgeOld(cutoff);
        return tokens + ended;
    }

    // ---------------------------------------------------------------- helpers

    private String mintRefreshToken(UserSession session, User user, Instant now) {
        String raw = Tokens.newOpaqueToken();
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setSession(session);
        token.setTokenHash(Tokens.sha256(raw));
        // Sliding idle timeout, capped by the session's absolute end.
        Instant idleEnd = now.plus(idleTtl);
        token.setExpiresAt(idleEnd.isBefore(session.getExpiresAt()) ? idleEnd : session.getExpiresAt());
        refreshTokens.save(token);
        return raw;
    }

    private void revoke(UserSession session, Instant now) {
        session.setRevokedAt(now);
        refreshTokens.revokeAllForSession(session.getId(), now);
    }

    private void revokeEverything(Long userId, Instant now) {
        sessions.revokeAllForUser(userId, now);
        refreshTokens.revokeAllForUser(userId, now);
    }

    /**
     * Emails the owner when a sign-in comes from neither an address nor a browser seen in
     * the account's recent sessions. Skipped for the very first sign-in (there is nothing
     * to compare against, and the owner is obviously present).
     */
    private void alertIfNewDevice(User user, UserSession session, Instant previousSignIn, Instant now) {
        if (!newSignInAlerts || previousSignIn == null) {
            return;
        }
        boolean known = sessions.seenBefore(user.getId(), session.getId(), now.minus(DEVICE_MEMORY),
                session.getIp(), session.getUserAgent());
        if (!known) {
            events.add(SecurityEventType.NEW_DEVICE_SIGN_IN, user, session.getUserAgent());
            email.sendNewSignInAlert(user.getEmail(), session.getIp(), session.getUserAgent(), now);
        }
    }
}
