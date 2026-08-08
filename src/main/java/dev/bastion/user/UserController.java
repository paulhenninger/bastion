package dev.bastion.user;

import dev.bastion.auth.RefreshTokenService;
import dev.bastion.auth.dto.AuthDtos.MessageResponse;
import dev.bastion.common.ApiException;
import dev.bastion.email.EmailService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/api/v1/users/me")
public class UserController {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokens;
    private final EmailService emailService;

    public UserController(UserRepository users,
                          PasswordEncoder passwordEncoder,
                          RefreshTokenService refreshTokens,
                          EmailService emailService) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokens = refreshTokens;
        this.emailService = emailService;
    }

    @GetMapping
    public ProfileResponse me(@AuthenticationPrincipal User user) {
        return ProfileResponse.from(user);
    }

    @PutMapping
    @Transactional
    public ProfileResponse update(@AuthenticationPrincipal User user,
                                  @Valid @RequestBody UpdateProfileRequest request) {
        User fresh = users.findById(user.getId()).orElseThrow();
        fresh.setName(request.name() == null ? null : request.name().trim());
        users.save(fresh);
        return ProfileResponse.from(fresh);
    }

    @PostMapping("/change-password")
    @Transactional
    public MessageResponse changePassword(@AuthenticationPrincipal User user,
                                          @Valid @RequestBody ChangePasswordRequest request) {
        User fresh = users.findById(user.getId()).orElseThrow();
        if (!passwordEncoder.matches(request.currentPassword(), fresh.getPasswordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Current password is incorrect");
        }
        fresh.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        users.save(fresh);
        // End every session; the SPA sends the user back through login.
        refreshTokens.revokeAllForUser(fresh.getId());
        emailService.sendPasswordChangedNotice(fresh.getEmail());
        return new MessageResponse("Password changed — sign in again on your devices");
    }

    // ------------------------------------------------------------------- DTOs

    public record UpdateProfileRequest(@Size(max = 100) String name) {
    }

    public record ChangePasswordRequest(
            @NotBlank @Size(max = 100) String currentPassword,
            @NotBlank @Size(min = 8, max = 100) String newPassword) {
    }

    public record ProfileResponse(Long id, String email, String name, String role,
                                  Instant createdAt, Instant lastLoginAt) {

        static ProfileResponse from(User user) {
            return new ProfileResponse(user.getId(), user.getEmail(), user.getName(),
                    user.getRole().name(), user.getCreatedAt(), user.getLastLoginAt());
        }
    }
}
