package dev.bastion.passkey;

import dev.bastion.session.AuthPrincipal;
import dev.bastion.session.ReauthService;
import dev.bastion.session.SessionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Passkey management for the signed-in user. Registration happens here; passwordless
 * sign-in is at {@code /api/v1/auth/passkey/*}. Adding or removing one requires a
 * fresh re-authentication.
 */
@RestController
@RequestMapping("/api/v1/users/me/passkeys")
public class PasskeyController {

    private final PasskeyService passkeys;
    private final ReauthService reauth;
    private final SessionService sessions;

    public PasskeyController(PasskeyService passkeys, ReauthService reauth, SessionService sessions) {
        this.passkeys = passkeys;
        this.reauth = reauth;
        this.sessions = sessions;
    }

    @GetMapping
    public List<PasskeyRow> list(@AuthenticationPrincipal AuthPrincipal me) {
        return passkeys.list(me.userId()).stream().map(PasskeyRow::from).toList();
    }

    @PostMapping("/options")
    public Map<String, Object> options(@AuthenticationPrincipal AuthPrincipal me) {
        reauth.require(me);
        return passkeys.registrationOptions(me.userId());
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PasskeyRow register(@AuthenticationPrincipal AuthPrincipal me,
                               @Valid @RequestBody RegisterRequest request) {
        reauth.require(me);
        PasskeyRow row = PasskeyRow.from(passkeys.register(me.userId(), request.attestationObject(),
                request.clientDataJSON(), request.transports(), request.label()));
        // The registration ceremony required user verification on the new authenticator.
        sessions.markStrong(me.sessionId());
        return row;
    }

    @PatchMapping("/{id}")
    public PasskeyRow rename(@AuthenticationPrincipal AuthPrincipal me, @PathVariable Long id,
                             @Valid @RequestBody RenameRequest request) {
        return PasskeyRow.from(passkeys.rename(me.userId(), id, request.label()));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthPrincipal me, @PathVariable Long id) {
        reauth.require(me);
        passkeys.delete(me.userId(), id);
    }

    public record RegisterRequest(
            @NotBlank @Size(max = 16384) String attestationObject,
            @NotBlank @Size(max = 4096) String clientDataJSON,
            @Size(max = 8) List<@Size(max = 32) String> transports,
            @Size(max = 100) String label) {
    }

    public record RenameRequest(@NotBlank @Size(max = 100) String label) {
    }

    public record PasskeyRow(Long id, String label, boolean synced, Instant createdAt, Instant lastUsedAt) {
        static PasskeyRow from(PasskeyCredential c) {
            return new PasskeyRow(c.getId(), c.getLabel(), c.isBackedUp(), c.getCreatedAt(), c.getLastUsedAt());
        }
    }
}
