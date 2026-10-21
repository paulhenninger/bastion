package dev.bastion.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.bastion.email.ValidEmail;
import dev.bastion.user.User;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request and response bodies for /api/v1/auth. Size caps here are coarse guards
 * against oversized input; the real password rules live in PasswordPolicy.
 */
public final class AuthDtos {

    private AuthDtos() {
    }

    public record SignupRequest(
            @ValidEmail String email,
            @NotBlank @Size(max = 1024) String password,
            @Size(max = 100) String name,
            @Size(max = 2048) String captchaToken) {
    }

    public record LoginRequest(
            @NotBlank @Size(max = 254) String email,
            @NotBlank @Size(max = 1024) String password) {
    }

    public record MfaRequest(
            @NotBlank @Size(max = 100) String mfaToken,
            @NotBlank @Size(max = 32) String code) {
    }

    public record VerifyEmailRequest(
            @NotBlank @Size(max = 100) String token,
            @NotBlank @Size(max = 1024) String password) {
    }

    public record EmailRequest(
            @NotBlank @Size(max = 254) String email,
            @Size(max = 2048) String captchaToken) {
    }

    public record ResetPasswordRequest(
            @NotBlank @Size(max = 100) String token,
            @NotBlank @Size(max = 1024) String newPassword) {
    }

    public record TokenRequest(
            @NotBlank @Size(max = 100) String token) {
    }

    /** A completed sign-in. {@code passwordBreached} asks the SPA to nudge a password change. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuthResponse(String accessToken, long expiresIn, UserSummary user, Boolean passwordBreached) {
    }

    /** The password was right; a second factor is owed at POST /auth/mfa. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record MfaChallengeResponse(boolean mfaRequired, String mfaToken, Boolean passwordBreached) {
    }

    public record UserSummary(Long id, String email, String name, String role, boolean mfaEnabled) {

        public static UserSummary from(User user) {
            return new UserSummary(user.getId(), user.getEmail(), user.getName(), user.getRole().name(),
                    user.isTotpEnabled());
        }
    }

    /** What the SPA needs before anyone signs in. Everything here is public by nature. */
    public record PublicConfig(String appName, boolean signupsOpen, int passwordMinLength,
                               int passwordMaxLength, String turnstileSiteKey) {
    }

    public record MessageResponse(String message) {
    }
}
