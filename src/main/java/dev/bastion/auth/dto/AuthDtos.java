package dev.bastion.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class AuthDtos {

    private AuthDtos() {
    }

    public record SignupRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(min = 8, max = 100) String password,
            @Size(max = 100) String name) {
    }

    public record LoginRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String password) {
    }

    public record ResendVerificationRequest(
            @NotBlank @Email @Size(max = 254) String email) {
    }

    public record ForgotPasswordRequest(
            @NotBlank @Email @Size(max = 254) String email) {
    }

    public record ResetPasswordRequest(
            @NotBlank @Size(max = 100) String token,
            @NotBlank @Size(min = 8, max = 100) String newPassword) {
    }

    public record AuthResponse(String accessToken, UserSummary user) {
    }

    public record UserSummary(Long id, String email, String name, String role) {
    }

    public record MessageResponse(String message) {
    }
}
