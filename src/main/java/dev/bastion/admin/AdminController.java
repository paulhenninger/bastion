package dev.bastion.admin;

import dev.bastion.auth.RefreshTokenService;
import dev.bastion.auth.dto.AuthDtos.MessageResponse;
import dev.bastion.common.ApiException;
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
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/**
 * User management. The whole {@code /api/v1/admin/**} tree is gated to ROLE_ADMIN
 * in SecurityConfig; every mutating action additionally refuses the acting admin's
 * own account — no self-demote, self-lock, or self-delete lockouts.
 */
@RestController
@RequestMapping("/api/v1/admin/users")
public class AdminController {

    private final UserRepository users;
    private final RefreshTokenService refreshTokens;

    public AdminController(UserRepository users, RefreshTokenService refreshTokens) {
        this.users = users;
        this.refreshTokens = refreshTokens;
    }

    @GetMapping
    public PagedResponse<AdminUserRow> list(@RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "20") int size) {
        int clampedSize = Math.max(1, Math.min(size, 100));
        Page<User> result = users.findAll(PageRequest.of(Math.max(0, page), clampedSize,
                Sort.by(Sort.Direction.DESC, "createdAt")));
        return new PagedResponse<>(
                result.getContent().stream().map(AdminUserRow::from).toList(),
                result.getNumber(), result.getSize(),
                result.getTotalElements(), result.getTotalPages());
    }

    @PutMapping("/{id}/role")
    @Transactional
    public AdminUserRow setRole(@AuthenticationPrincipal User admin,
                                @PathVariable Long id,
                                @Valid @RequestBody RoleRequest request) {
        User target = requireOther(admin, id);
        target.setRole(request.role());
        return AdminUserRow.from(users.save(target));
    }

    @PutMapping("/{id}/locked")
    @Transactional
    public AdminUserRow setLocked(@AuthenticationPrincipal User admin,
                                  @PathVariable Long id,
                                  @Valid @RequestBody LockedRequest request) {
        boolean locked = Boolean.TRUE.equals(request.locked());
        User target = requireOther(admin, id);
        target.setLocked(locked);
        User saved = users.save(target);
        if (locked) {
            // A lock must not be outlived by an active session.
            refreshTokens.revokeAllForUser(saved.getId());
        }
        return AdminUserRow.from(saved);
    }

    @DeleteMapping("/{id}")
    @Transactional
    public MessageResponse delete(@AuthenticationPrincipal User admin, @PathVariable Long id) {
        User target = requireOther(admin, id);
        users.delete(target);
        return new MessageResponse("Account deleted");
    }

    private User requireOther(User admin, Long id) {
        if (admin.getId().equals(id)) {
            throw new ApiException(HttpStatus.FORBIDDEN, "You cannot modify your own account here");
        }
        return users.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "No such user"));
    }

    // ------------------------------------------------------------------- DTOs

    public record RoleRequest(@NotNull Role role) {
    }

    public record LockedRequest(@NotNull Boolean locked) {
    }

    public record AdminUserRow(Long id, String email, String name, String role,
                               boolean enabled, boolean locked,
                               Instant createdAt, Instant lastLoginAt) {

        static AdminUserRow from(User user) {
            return new AdminUserRow(user.getId(), user.getEmail(), user.getName(),
                    user.getRole().name(), user.isEnabled(), user.isLocked(),
                    user.getCreatedAt(), user.getLastLoginAt());
        }
    }

    public record PagedResponse<T>(List<T> content, int page, int size,
                                   long totalElements, int totalPages) {
    }
}
