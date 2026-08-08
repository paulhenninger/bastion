package dev.bastion.auth;

import dev.bastion.auth.dto.AuthDtos.AuthResponse;
import dev.bastion.auth.dto.AuthDtos.ForgotPasswordRequest;
import dev.bastion.auth.dto.AuthDtos.LoginRequest;
import dev.bastion.auth.dto.AuthDtos.MessageResponse;
import dev.bastion.auth.dto.AuthDtos.ResendVerificationRequest;
import dev.bastion.auth.dto.AuthDtos.ResetPasswordRequest;
import dev.bastion.auth.dto.AuthDtos.SignupRequest;
import dev.bastion.auth.dto.AuthDtos.UserSummary;
import dev.bastion.config.AppProperties;
import dev.bastion.user.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * The refresh token travels only as an HttpOnly SameSite=Lax cookie scoped to this
 * controller's path — JavaScript never sees it, and it isn't sent on any other route.
 * The access token goes to the SPA in the response body.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Validated
public class AuthController {

    static final String REFRESH_COOKIE = "bastion_refresh";
    private static final String COOKIE_PATH = "/api/v1/auth";

    private final AuthService authService;
    private final AppProperties props;
    private final boolean secureCookies;

    public AuthController(AuthService authService, AppProperties props) {
        this.authService = authService;
        this.props = props;
        // Secure flag follows how the app is reached; localhost dev is plain http.
        this.secureCookies = props.baseUrl() != null && props.baseUrl().startsWith("https");
    }

    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> signup(@Valid @RequestBody SignupRequest request) {
        authService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new MessageResponse("Check your email to verify your account"));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<AuthResponse> verifyEmail(@RequestParam("token") @NotBlank String token) {
        AuthService.Session session = authService.verifyEmail(token);
        return withRefreshCookie(session);
    }

    @PostMapping("/resend-verification")
    public MessageResponse resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        authService.resendVerification(request.email());
        return new MessageResponse("If that address needs verification, a new link is on its way");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthService.Session session = authService.login(request.email(), request.password());
        return withRefreshCookie(session);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @CookieValue(value = REFRESH_COOKIE, required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return unauthorizedWithClearedCookie();
        }
        return authService.refresh(refreshToken)
                .map(this::withRefreshCookie)
                .orElseGet(this::unauthorizedWithClearedCookie);
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(
            @CookieValue(value = REFRESH_COOKIE, required = false) String refreshToken) {
        if (refreshToken != null && !refreshToken.isBlank()) {
            authService.logout(refreshToken);
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearedCookie().toString())
                .body(new MessageResponse("Signed out"));
    }

    @PostMapping("/forgot-password")
    public MessageResponse forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request.email());
        return new MessageResponse("If an account exists for that address, a reset link is on its way");
    }

    @PostMapping("/reset-password")
    public MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.token(), request.newPassword());
        return new MessageResponse("Password updated — you can sign in now");
    }

    // ----------------------------------------------------------------- helpers

    private ResponseEntity<AuthResponse> withRefreshCookie(AuthService.Session session) {
        User user = session.user();
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, session.refreshToken())
                .httpOnly(true)
                .secure(secureCookies)
                .sameSite("Lax")
                .path(COOKIE_PATH)
                .maxAge(Duration.ofDays(props.refreshTokenDays()))
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new AuthResponse(session.accessToken(),
                        new UserSummary(user.getId(), user.getEmail(), user.getName(),
                                user.getRole().name())));
    }

    private ResponseEntity<AuthResponse> unauthorizedWithClearedCookie() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, clearedCookie().toString())
                .build();
    }

    private ResponseCookie clearedCookie() {
        return ResponseCookie.from(REFRESH_COOKIE, "")
                .httpOnly(true)
                .secure(secureCookies)
                .sameSite("Lax")
                .path(COOKIE_PATH)
                .maxAge(0)
                .build();
    }
}
