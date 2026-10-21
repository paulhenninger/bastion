package dev.bastion.mfa;

import dev.bastion.session.AuthPrincipal;
import dev.bastion.session.ReauthService;
import dev.bastion.session.SessionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Two-factor settings for the signed-in user. Every change requires a fresh
 * re-authentication: a borrowed session must not be able to point the second factor
 * at an attacker's phone, or switch it off.
 */
@RestController
@RequestMapping("/api/v1/users/me/mfa")
public class MfaController {

    private final MfaService mfa;
    private final ReauthService reauth;
    private final SessionService sessions;

    public MfaController(MfaService mfa, ReauthService reauth, SessionService sessions) {
        this.mfa = mfa;
        this.reauth = reauth;
        this.sessions = sessions;
    }

    @GetMapping
    public MfaService.Status status(@AuthenticationPrincipal AuthPrincipal me) {
        return mfa.status(me.userId());
    }

    /** A fresh secret and its otpauth:// URI (for the QR code). Not enforced until enabled. */
    @PostMapping("/totp/setup")
    public ResponseEntity<MfaService.TotpSetup> setup(@AuthenticationPrincipal AuthPrincipal me) {
        reauth.require(me);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(mfa.setupTotp(me.userId()));
    }

    /** Proves a code from the new secret, turns TOTP on, and returns recovery codes — once. */
    @PostMapping("/totp/enable")
    public ResponseEntity<Map<String, List<String>>> enable(@AuthenticationPrincipal AuthPrincipal me,
                                                            @Valid @RequestBody CodeRequest request) {
        reauth.require(me);
        List<String> codes = mfa.enableTotp(me.userId(), request.code());
        // Password at sign-in + a code from the enrolled device just now: two factors.
        sessions.markStrong(me.sessionId());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Map.of("recoveryCodes", codes));
    }

    @PostMapping("/totp/disable")
    public Map<String, Boolean> disable(@AuthenticationPrincipal AuthPrincipal me) {
        reauth.require(me);
        mfa.disableTotp(me.userId());
        return Map.of("totpEnabled", false);
    }

    @PostMapping("/recovery-codes")
    public ResponseEntity<Map<String, List<String>>> regenerate(@AuthenticationPrincipal AuthPrincipal me) {
        reauth.require(me);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(Map.of("recoveryCodes", mfa.regenerateRecoveryCodes(me.userId())));
    }

    public record CodeRequest(@NotBlank @Size(max = 32) String code) {
    }
}
