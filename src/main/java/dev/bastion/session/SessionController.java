package dev.bastion.session;

import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.common.ApiException;
import dev.bastion.passkey.PasskeyService;
import dev.bastion.passkey.PasskeyService.Assertion;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The caller's sessions ("where you're signed in") and step-up re-authentication.
 */
@RestController
@RequestMapping("/api/v1/users/me")
public class SessionController {

    private final SessionService sessions;
    private final ReauthService reauth;
    private final PasskeyService passkeys;
    private final UserRepository users;
    private final SecurityEvents events;

    public SessionController(SessionService sessions, ReauthService reauth, PasskeyService passkeys,
                             UserRepository users, SecurityEvents events) {
        this.sessions = sessions;
        this.reauth = reauth;
        this.passkeys = passkeys;
        this.users = users;
        this.events = events;
    }

    @GetMapping("/sessions")
    public List<SessionRow> list(@AuthenticationPrincipal AuthPrincipal me) {
        return sessions.active(me.userId()).stream()
                .map(s -> new SessionRow(s.getPublicId(), s.getAuthMethod().name(), s.getIp(), s.getUserAgent(),
                        s.getCreatedAt(), s.getLastSeenAt(), s.getExpiresAt(), s.getId().equals(me.sessionId())))
                .toList();
    }

    @DeleteMapping("/sessions/{publicId}")
    public Map<String, Object> revoke(@AuthenticationPrincipal AuthPrincipal me, @PathVariable String publicId) {
        if (publicId.length() > 64 || !sessions.revoke(me.userId(), publicId)) {
            throw ApiException.notFound("Session not found");
        }
        events.add(SecurityEventType.SESSION_REVOKED, user(me));
        return Map.of("revoked", 1);
    }

    @PostMapping("/sessions/revoke-others")
    public Map<String, Object> revokeOthers(@AuthenticationPrincipal AuthPrincipal me) {
        int ended = sessions.revokeOthers(me.userId(), me.sessionId());
        events.add(SecurityEventType.OTHER_SESSIONS_REVOKED, user(me), ended + " ended");
        return Map.of("revoked", ended);
    }

    // ------------------------------------------------------------- step-up

    /** When the current sudo window closes, and which ways of re-authenticating apply. */
    @GetMapping("/reauth")
    public ReauthStatus status(@AuthenticationPrincipal AuthPrincipal me) {
        User user = user(me);
        Instant until = me.reauthAt() == null ? null : me.reauthAt().plus(sessions.reauthWindow());
        return new ReauthStatus(sessions.isRecentlyReauthenticated(me) ? until : null,
                user.isTotpEnabled(), !passkeys.list(me.userId()).isEmpty());
    }

    @PostMapping("/reauth")
    public Map<String, Object> reauthWithPassword(@AuthenticationPrincipal AuthPrincipal me,
                                                  @Valid @RequestBody ReauthRequest request) {
        reauth.withPassword(me, request.password(), request.code());
        return Map.of("reauthenticated", true);
    }

    @PostMapping("/reauth/passkey/options")
    public Map<String, Object> reauthPasskeyOptions(@AuthenticationPrincipal AuthPrincipal me) {
        return passkeys.reauthOptions(me.userId());
    }

    @PostMapping("/reauth/passkey")
    public Map<String, Object> reauthWithPasskey(@AuthenticationPrincipal AuthPrincipal me,
                                                 @Valid @RequestBody AssertionRequest request) {
        passkeys.reauthenticate(me.userId(), request.toAssertion());
        sessions.markReauthenticated(me.sessionId());
        events.add(SecurityEventType.REAUTHENTICATED, user(me), "passkey");
        return Map.of("reauthenticated", true);
    }

    private User user(AuthPrincipal me) {
        return users.findById(me.userId()).orElseThrow();
    }

    // ------------------------------------------------------------------- DTOs

    public record SessionRow(String id, String method, String ip, String userAgent, Instant createdAt,
                             Instant lastSeenAt, Instant expiresAt, boolean current) {
    }

    public record ReauthStatus(Instant reauthenticatedUntil, boolean totpEnabled, boolean hasPasskeys) {
    }

    public record ReauthRequest(@NotBlank @Size(max = 1024) String password, @Size(max = 32) String code) {
    }

    /** A WebAuthn assertion as the SPA serialises it: every binary field base64url. */
    public record AssertionRequest(
            @NotBlank @Size(max = 1400) String credentialId,
            @NotBlank @Size(max = 4096) String clientDataJSON,
            @NotBlank @Size(max = 4096) String authenticatorData,
            @NotBlank @Size(max = 2048) String signature,
            @Size(max = 128) String userHandle) {

        public Assertion toAssertion() {
            return new Assertion(credentialId, clientDataJSON, authenticatorData, signature, userHandle);
        }
    }
}
