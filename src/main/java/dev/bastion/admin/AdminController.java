package dev.bastion.admin;

import dev.bastion.audit.SecurityEvent;
import dev.bastion.audit.SecurityEventRepository;
import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.auth.dto.AuthDtos.MessageResponse;
import dev.bastion.common.ApiException;
import dev.bastion.email.EmailService;
import dev.bastion.mfa.MfaService;
import dev.bastion.passkey.PasskeyService;
import dev.bastion.session.AuthPrincipal;
import dev.bastion.session.ReauthService;
import dev.bastion.session.SessionService;
import dev.bastion.user.Role;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/**
 * User management. The whole {@code /api/v1/admin/**} tree requires ROLE_ADMIN (in
 * SecurityConfig) and, by default, a session that signed in with two factors
 * ({@link AdminMfaInterceptor}). On top of that:
 * <ul>
 *   <li>every mutating action requires a fresh re-authentication — a hijacked admin
 *       session is the most valuable thing in the system;</li>
 *   <li>every action refuses the acting admin's own account — no self-demote, self-lock
 *       or self-delete lockouts, so at least one admin always remains;</li>
 *   <li>every action is written to the security log with the admin as actor, and the
 *       affected user is emailed.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {

    private final UserRepository users;
    private final SessionService sessions;
    private final ReauthService reauth;
    private final MfaService mfa;
    private final PasskeyService passkeys;
    private final SecurityEvents events;
    private final SecurityEventRepository eventRepository;
    private final SettingsService settings;
    private final EmailService email;

    public AdminController(UserRepository users, SessionService sessions, ReauthService reauth, MfaService mfa,
                           PasskeyService passkeys, SecurityEvents events, SecurityEventRepository eventRepository,
                           SettingsService settings, EmailService email) {
        this.users = users;
        this.sessions = sessions;
        this.reauth = reauth;
        this.mfa = mfa;
        this.passkeys = passkeys;
        this.events = events;
        this.eventRepository = eventRepository;
        this.settings = settings;
        this.email = email;
    }

    // ------------------------------------------------------------------ users

    @GetMapping("/users")
    public PagedResponse<AdminUserRow> list(@RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "20") int size,
                                            @RequestParam(defaultValue = "") String q) {
        PageRequest pageable = PageRequest.of(Math.max(0, Math.min(page, 10_000)), Math.max(1, Math.min(size, 100)),
                Sort.by(Sort.Direction.DESC, "createdAt"));
        String query = q.strip();
        if (query.length() > 100) {
            throw ApiException.badRequest("Search is too long");
        }
        Page<User> result = query.isEmpty() ? users.findAll(pageable) : users.search(query, pageable);
        return PagedResponse.of(result.map(AdminUserRow::from));
    }

    @GetMapping("/users/{id}")
    public AdminUserDetail detail(@PathVariable Long id) {
        User user = users.findById(id).orElseThrow(() -> ApiException.notFound("No such user"));
        return new AdminUserDetail(AdminUserRow.from(user), user.getPasswordChangedAt(),
                passkeys.list(id).size(),
                sessions.active(id).stream().map(s -> new SessionRow(s.getAuthMethod().name(), s.getIp(),
                        s.getUserAgent(), s.getCreatedAt(), s.getLastSeenAt())).toList(),
                eventRepository.findTop50ByUserIdOrderByOccurredAtDescIdDesc(id).stream()
                        .map(EventRow::from).toList());
    }

    @PutMapping("/users/{id}/role")
    @Transactional
    public AdminUserRow setRole(@AuthenticationPrincipal AuthPrincipal admin, @PathVariable Long id,
                                @Valid @RequestBody RoleRequest request) {
        reauth.require(admin);
        User target = requireOther(admin, id);
        if (target.getRole() == request.role()) {
            return AdminUserRow.from(target);
        }
        target.setRole(request.role());
        events.record(SecurityEventType.ADMIN_ROLE_CHANGED, target, actor(admin), "now " + request.role());
        email.sendSecurityNotice(target.getEmail(), "Your account role changed",
                request.role() == Role.ADMIN
                        ? "An administrator gave your account administrator access."
                        : "An administrator removed administrator access from your account.");
        return AdminUserRow.from(target);
    }

    @PutMapping("/users/{id}/locked")
    @Transactional
    public AdminUserRow setLocked(@AuthenticationPrincipal AuthPrincipal admin, @PathVariable Long id,
                                  @Valid @RequestBody LockedRequest request) {
        reauth.require(admin);
        boolean locked = Boolean.TRUE.equals(request.locked());
        User target = requireOther(admin, id);
        target.setLocked(locked);
        users.saveAndFlush(target);
        if (locked) {
            // A lock must not be outlived by an active session.
            sessions.revokeAll(target.getId());
        }
        events.record(locked ? SecurityEventType.ADMIN_LOCKED : SecurityEventType.ADMIN_UNLOCKED,
                target, actor(admin), null);
        return AdminUserRow.from(target);
    }

    /** Signs the user out everywhere — e.g. after they report a lost device. */
    @PostMapping("/users/{id}/sessions/revoke")
    public MessageResponse revokeSessions(@AuthenticationPrincipal AuthPrincipal admin, @PathVariable Long id) {
        User target = requireOther(admin, id);
        sessions.revokeAll(target.getId());
        events.record(SecurityEventType.ADMIN_REVOKED_SESSIONS, target, actor(admin), null);
        return new MessageResponse("Signed out everywhere");
    }

    /** For an owner who lost both their authenticator and their recovery codes. */
    @DeleteMapping("/users/{id}/mfa")
    public MessageResponse resetMfa(@AuthenticationPrincipal AuthPrincipal admin, @PathVariable Long id) {
        reauth.require(admin);
        User target = requireOther(admin, id);
        mfa.adminReset(target.getId(), actor(admin));
        sessions.revokeAll(target.getId());
        return new MessageResponse("Two-factor authentication reset");
    }

    @DeleteMapping("/users/{id}")
    @Transactional
    public MessageResponse delete(@AuthenticationPrincipal AuthPrincipal admin, @PathVariable Long id) {
        reauth.require(admin);
        User target = requireOther(admin, id);
        events.record(SecurityEventType.ADMIN_DELETED_ACCOUNT, target, actor(admin), null);
        users.delete(target);
        return new MessageResponse("Account deleted");
    }

    // --------------------------------------------------------- security log

    @GetMapping("/security-events")
    public PagedResponse<EventRow> securityEvents(@RequestParam(required = false) Long userId,
                                                  @RequestParam(required = false) String email,
                                                  @RequestParam(required = false) String ip,
                                                  @RequestParam(required = false) SecurityEventType type,
                                                  @RequestParam(defaultValue = "0") int page,
                                                  @RequestParam(defaultValue = "50") int size) {
        if ((email != null && email.length() > 254) || (ip != null && ip.length() > 45)) {
            throw ApiException.badRequest("Filter is too long");
        }
        PageRequest pageable = PageRequest.of(Math.max(0, Math.min(page, 10_000)), Math.max(1, Math.min(size, 200)));
        return PagedResponse.of(eventRepository.search(userId, blankToNull(email, true), blankToNull(ip, false),
                type, pageable).map(EventRow::from));
    }

    // -------------------------------------------------------------- settings

    @GetMapping("/settings")
    public SettingsResponse getSettings() {
        return new SettingsResponse(settings.signupsOpen());
    }

    @PutMapping("/settings")
    public SettingsResponse putSettings(@AuthenticationPrincipal AuthPrincipal admin,
                                        @Valid @RequestBody SettingsResponse request) {
        reauth.require(admin);
        settings.setSignupsOpen(request.signupsOpen(), actor(admin));
        return new SettingsResponse(settings.signupsOpen());
    }

    // ---------------------------------------------------------------- helpers

    private User requireOther(AuthPrincipal admin, Long id) {
        if (admin.userId().equals(id)) {
            throw new ApiException(HttpStatus.FORBIDDEN, "You can't do that to your own account here");
        }
        return users.findById(id).orElseThrow(() -> ApiException.notFound("No such user"));
    }

    private User actor(AuthPrincipal admin) {
        return users.getReferenceById(admin.userId());
    }

    private static String blankToNull(String value, boolean lower) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return lower ? value.strip().toLowerCase(java.util.Locale.ROOT) : value.strip();
    }

    // ------------------------------------------------------------------- DTOs

    public record RoleRequest(@NotNull Role role) {
    }

    public record LockedRequest(@NotNull Boolean locked) {
    }

    public record SettingsResponse(boolean signupsOpen) {
    }

    public record AdminUserRow(Long id, String email, String name, String role, boolean enabled, boolean locked,
                               boolean mfaEnabled, Instant createdAt, Instant lastLoginAt) {
        static AdminUserRow from(User user) {
            return new AdminUserRow(user.getId(), user.getEmail(), user.getName(), user.getRole().name(),
                    user.isEnabled(), user.isLocked(), user.isTotpEnabled(), user.getCreatedAt(),
                    user.getLastLoginAt());
        }
    }

    public record SessionRow(String method, String ip, String userAgent, Instant createdAt, Instant lastSeenAt) {
    }

    public record AdminUserDetail(AdminUserRow user, Instant passwordChangedAt, int passkeys,
                                  List<SessionRow> sessions, List<EventRow> recentEvents) {
    }

    public record EventRow(Long id, Instant occurredAt, String type, Long userId, String email, Long actorUserId,
                           String ip, String userAgent, String detail) {
        static EventRow from(SecurityEvent e) {
            return new EventRow(e.getId(), e.getOccurredAt(), e.getType().name(), e.getUserId(),
                    e.getSubjectEmail(), e.getActorUserId(), e.getIp(), e.getUserAgent(), e.getDetail());
        }
    }

    public record PagedResponse<T>(List<T> content, int page, int size, long totalElements, int totalPages) {
        static <T> PagedResponse<T> of(Page<T> page) {
            return new PagedResponse<>(page.getContent(), page.getNumber(), page.getSize(),
                    page.getTotalElements(), page.getTotalPages());
        }
    }
}
