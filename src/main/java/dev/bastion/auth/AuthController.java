package dev.bastion.auth;

import dev.bastion.admin.SettingsService;
import dev.bastion.auth.dto.AuthDtos.AuthResponse;
import dev.bastion.auth.dto.AuthDtos.EmailRequest;
import dev.bastion.auth.dto.AuthDtos.LoginRequest;
import dev.bastion.auth.dto.AuthDtos.MessageResponse;
import dev.bastion.auth.dto.AuthDtos.MfaChallengeResponse;
import dev.bastion.auth.dto.AuthDtos.MfaRequest;
import dev.bastion.auth.dto.AuthDtos.PublicConfig;
import dev.bastion.auth.dto.AuthDtos.ResetPasswordRequest;
import dev.bastion.auth.dto.AuthDtos.SignupRequest;
import dev.bastion.auth.dto.AuthDtos.TokenRequest;
import dev.bastion.auth.dto.AuthDtos.UserSummary;
import dev.bastion.auth.dto.AuthDtos.VerifyEmailRequest;
import dev.bastion.common.ApiException;
import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailDeliverability;
import dev.bastion.security.ClientInfo;
import dev.bastion.security.JwtService;
import dev.bastion.security.PasswordPolicy;
import dev.bastion.security.TurnstileVerifier;
import dev.bastion.passkey.PasskeyService;
import dev.bastion.session.SessionController.AssertionRequest;
import dev.bastion.session.SessionService.Issued;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Anonymous endpoints: everything before (and the end of) a session.
 *
 * <p>The refresh token travels only as a cookie: {@code HttpOnly} (no script can read
 * it), {@code Secure} when served over https, {@code SameSite=Strict} (never sent on a
 * cross-site request) and scoped to {@code /api/v1/auth} (never sent to the rest of the
 * API). The access token goes to the SPA in the response body and lives in memory only.
 *
 * <p>Cookie-authenticated endpoints (refresh, logout) also require an
 * {@code X-Bastion-Client} header. A cross-site page can't add a custom header without
 * a CORS preflight that the server refuses, so this is CSRF defence that doesn't depend
 * on every browser honouring SameSite.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    public static final String REFRESH_COOKIE = "bastion_refresh";
    public static final String CLIENT_HEADER = "X-Bastion-Client";
    private static final String COOKIE_PATH = "/api/v1/auth";

    private final AuthService auth;
    private final SettingsService settings;
    private final TurnstileVerifier turnstile;
    private final EmailDeliverability deliverability;
    private final PasswordPolicy passwordPolicy;
    private final JwtService jwt;
    private final PasskeyService passkeys;
    private final AppProperties props;

    public AuthController(AuthService auth, SettingsService settings, TurnstileVerifier turnstile,
                          EmailDeliverability deliverability, PasswordPolicy passwordPolicy,
                          JwtService jwt, PasskeyService passkeys, AppProperties props) {
        this.auth = auth;
        this.settings = settings;
        this.turnstile = turnstile;
        this.deliverability = deliverability;
        this.passwordPolicy = passwordPolicy;
        this.jwt = jwt;
        this.passkeys = passkeys;
        this.props = props;
    }

    @GetMapping("/config")
    public PublicConfig config() {
        return new PublicConfig(props.name(), settings.signupsOpen(), passwordPolicy.minLength(),
                passwordPolicy.maxLength(), turnstile.siteKey());
    }

    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> signup(@Valid @RequestBody SignupRequest request,
                                                  HttpServletRequest http) {
        requireHuman(request.captchaToken(), http);
        // A property of the address being claimed, never of an account: safe to state.
        String problem = deliverability.problem(request.email());
        if (problem != null) {
            throw ApiException.badRequest(problem);
        }
        auth.signup(request.email(), request.password(), request.name());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new MessageResponse("Check your email for a link to activate your account"));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<AuthResponse> verifyEmail(@Valid @RequestBody VerifyEmailRequest request,
                                                    HttpServletRequest http) {
        return withSession(auth.verifyEmail(request.token(), request.password(), ClientInfo.of(http)), null);
    }

    @PostMapping("/resend-verification")
    public MessageResponse resendVerification(@Valid @RequestBody EmailRequest request, HttpServletRequest http) {
        requireHuman(request.captchaToken(), http);
        auth.resendVerification(request.email());
        return new MessageResponse("If that address needs verifying, a new link is on its way");
    }

    /** Password correct → a session, or (two-factor on) a challenge for {@code /mfa}. */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        AuthService.LoginResult result = auth.login(request.email(), request.password(), ClientInfo.of(http));
        Boolean breached = result.passwordBreached() ? Boolean.TRUE : null;
        if (result.mfaToken() != null) {
            return ResponseEntity.ok()
                    .cacheControl(CacheControl.noStore())
                    .body(new MfaChallengeResponse(true, result.mfaToken(), breached));
        }
        return withSession(result.session(), breached);
    }

    @PostMapping("/mfa")
    public ResponseEntity<AuthResponse> mfa(@Valid @RequestBody MfaRequest request, HttpServletRequest http) {
        return withSession(auth.completeMfa(request.mfaToken(), request.code(), ClientInfo.of(http)), null);
    }

    /** Options for a usernameless passkey sign-in ({@code navigator.credentials.get()}). */
    @PostMapping("/passkey/options")
    public java.util.Map<String, Object> passkeyOptions() {
        return passkeys.authenticationOptions();
    }

    @PostMapping("/passkey/verify")
    public ResponseEntity<AuthResponse> passkeyVerify(@Valid @RequestBody AssertionRequest request,
                                                      HttpServletRequest http) {
        return withSession(auth.passkeyLogin(request.toAssertion(), ClientInfo.of(http)), null);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @RequestHeader(value = CLIENT_HEADER, required = false) String client,
            @CookieValue(value = REFRESH_COOKIE, required = false) String refreshToken) {
        requireClientHeader(client);
        if (refreshToken == null || refreshToken.isBlank() || refreshToken.length() > 100) {
            return unauthorizedWithClearedCookie();
        }
        return auth.refresh(refreshToken)
                .map(issued -> withSession(issued, null))
                .orElseGet(this::unauthorizedWithClearedCookie);
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(
            @RequestHeader(value = CLIENT_HEADER, required = false) String client,
            @CookieValue(value = REFRESH_COOKIE, required = false) String refreshToken) {
        requireClientHeader(client);
        if (refreshToken != null && !refreshToken.isBlank() && refreshToken.length() <= 100) {
            auth.logout(refreshToken);
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie("", Duration.ZERO).toString())
                .body(new MessageResponse("Signed out"));
    }

    @PostMapping("/forgot-password")
    public MessageResponse forgotPassword(@Valid @RequestBody EmailRequest request, HttpServletRequest http) {
        requireHuman(request.captchaToken(), http);
        auth.forgotPassword(request.email());
        return new MessageResponse("If an account exists for that address, a reset link is on its way");
    }

    @PostMapping("/reset-password")
    public MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        auth.resetPassword(request.token(), request.newPassword());
        return new MessageResponse("Password updated — you can sign in now");
    }

    @PostMapping("/confirm-email-change")
    public MessageResponse confirmEmailChange(@Valid @RequestBody TokenRequest request) {
        auth.confirmEmailChange(request.token());
        return new MessageResponse("Email address updated — please sign in with your new address");
    }

    // ----------------------------------------------------------------- helpers

    private void requireHuman(String captchaToken, HttpServletRequest http) {
        if (!turnstile.verify(captchaToken, ClientInfo.ip(http))) {
            throw ApiException.badRequest("Please complete the \"I'm human\" check and try again");
        }
    }

    private static void requireClientHeader(String value) {
        if (value == null || value.isBlank()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Missing " + CLIENT_HEADER + " header");
        }
    }

    private ResponseEntity<AuthResponse> withSession(Issued issued, Boolean passwordBreached) {
        Duration cookieLife = Duration.between(java.time.Instant.now(), issued.session().getExpiresAt());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, cookie(issued.refreshToken(), cookieLife).toString())
                .body(new AuthResponse(issued.accessToken(), jwt.accessTokenSeconds(),
                        UserSummary.from(issued.user()), passwordBreached));
    }

    private ResponseEntity<AuthResponse> unauthorizedWithClearedCookie() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, cookie("", Duration.ZERO).toString())
                .build();
    }

    private ResponseCookie cookie(String value, Duration maxAge) {
        return ResponseCookie.from(REFRESH_COOKIE, value)
                .httpOnly(true)
                .secure(props.secureCookies())
                .sameSite("Strict")
                .path(COOKIE_PATH)
                .maxAge(maxAge)
                .build();
    }
}
