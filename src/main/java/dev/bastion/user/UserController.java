package dev.bastion.user;

import dev.bastion.audit.SecurityEvents;
import dev.bastion.auth.AccountService;
import dev.bastion.auth.dto.AuthDtos.MessageResponse;
import dev.bastion.email.ValidEmail;
import dev.bastion.session.AuthPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** The signed-in user's own account. Every route acts on the caller — no ids, no IDOR. */
@RestController
@RequestMapping("/api/v1/users/me")
public class UserController {

    private final UserRepository users;
    private final AccountService accounts;
    private final SecurityEvents events;

    public UserController(UserRepository users, AccountService accounts, SecurityEvents events) {
        this.users = users;
        this.accounts = accounts;
        this.events = events;
    }

    @GetMapping
    public ProfileResponse me(@AuthenticationPrincipal AuthPrincipal me) {
        return ProfileResponse.from(users.findById(me.userId()).orElseThrow(), me);
    }

    @PutMapping
    @Transactional
    public ProfileResponse update(@AuthenticationPrincipal AuthPrincipal me,
                                  @Valid @RequestBody UpdateProfileRequest request) {
        User user = users.findById(me.userId()).orElseThrow();
        String name = request.name() == null ? null : request.name().replaceAll("\\p{Cntrl}", " ").strip();
        user.setName(name == null || name.isEmpty() ? null : name);
        return ProfileResponse.from(user, me);
    }

    @PostMapping("/change-password")
    public MessageResponse changePassword(@AuthenticationPrincipal AuthPrincipal me,
                                          @Valid @RequestBody ChangePasswordRequest request) {
        accounts.changePassword(me, request.currentPassword(), request.newPassword(), request.code());
        return new MessageResponse("Password changed. Your other devices were signed out.");
    }

    @PostMapping("/email")
    public MessageResponse changeEmail(@AuthenticationPrincipal AuthPrincipal me,
                                       @Valid @RequestBody ChangeEmailRequest request) {
        accounts.requestEmailChange(me, request.newEmail());
        return new MessageResponse("We've sent a confirmation link to " + request.newEmail().trim()
                + ". Your address changes when you click it.");
    }

    @DeleteMapping
    public MessageResponse delete(@AuthenticationPrincipal AuthPrincipal me) {
        accounts.deleteAccount(me);
        return new MessageResponse("Your account has been deleted");
    }

    @GetMapping("/export")
    public ResponseEntity<Map<String, Object>> export(@AuthenticationPrincipal AuthPrincipal me) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"account-export.json\"")
                .body(accounts.export(me));
    }

    /** The account's own security log: sign-ins, failures, credential changes. */
    @GetMapping("/activity")
    public List<ActivityRow> activity(@AuthenticationPrincipal AuthPrincipal me) {
        return events.recentFor(me.userId()).stream()
                .map(e -> new ActivityRow(e.getOccurredAt(), e.getType().name(), e.getIp(),
                        e.getUserAgent(), e.getDetail()))
                .toList();
    }

    // ------------------------------------------------------------------- DTOs

    public record UpdateProfileRequest(@Size(max = 100) String name) {
    }

    public record ChangePasswordRequest(
            @NotBlank @Size(max = 1024) String currentPassword,
            @NotBlank @Size(max = 1024) String newPassword,
            @Size(max = 32) String code) {
    }

    public record ChangeEmailRequest(@ValidEmail String newEmail) {
    }

    public record ActivityRow(Instant occurredAt, String type, String ip, String userAgent, String detail) {
    }

    public record ProfileResponse(Long id, String email, String name, String role, boolean mfaEnabled,
                                  boolean strongSession, Instant createdAt, Instant lastLoginAt,
                                  Instant passwordChangedAt) {

        static ProfileResponse from(User user, AuthPrincipal me) {
            return new ProfileResponse(user.getId(), user.getEmail(), user.getName(), user.getRole().name(),
                    user.isTotpEnabled(), me.strongAuth(), user.getCreatedAt(), user.getLastLoginAt(),
                    user.getPasswordChangedAt());
        }
    }
}
