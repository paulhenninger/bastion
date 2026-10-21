package dev.bastion;

import dev.bastion.support.IntegrationTest;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** TOTP enrolment, the two-step sign-in, recovery codes, and step-up re-authentication. */
class MfaIntegrationTest extends IntegrationTest {

    private static final String EMAIL = "mfa.user@example.com";

    private String startLogin() throws Exception {
        JsonNode challenge = body(login(EMAIL, PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaRequired").value(true))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andReturn());
        return challenge.get("mfaToken").asString();
    }

    private org.springframework.test.web.servlet.ResultActions completeLogin(String mfaToken, String code) throws Exception {
        return mvc.perform(postJson("/api/v1/auth/mfa", Map.of("mfaToken", mfaToken, "code", code)));
    }

    @Test
    void enablingTotpMakesSignInTakeTwoSteps() throws Exception {
        Session session = newAccount(EMAIL);
        Totp totp = enableTotp(session);
        assertThat(totp.recoveryCodes()).hasSize(10).allMatch(c -> c.matches("[A-Z2-9]{5}-[A-Z2-9]{5}"));
        verify(email).sendSecurityNotice(eq(EMAIL), eq("Two-factor authentication turned on"), anyString());

        String mfaToken = startLogin();
        completeLogin(mfaToken, "000000").andExpect(status().isUnauthorized());
        String code = totpCode(totp.secret(), 0);
        Session signedIn = session(completeLogin(mfaToken, code).andExpect(status().isOk()).andReturn());
        mvc.perform(as(signedIn, get("/api/v1/users/me")))
                .andExpect(jsonPath("$.mfaEnabled").value(true))
                .andExpect(jsonPath("$.strongSession").value(true));

        // The challenge is single-use, and so is the code (replay within its 30 s window).
        completeLogin(mfaToken, code).andExpect(status().isUnauthorized());
        completeLogin(startLogin(), code).andExpect(status().isUnauthorized());
    }

    @Test
    void aChallengeAllowsFiveGuessesThenDies() throws Exception {
        Totp totp = enableTotp(newAccount(EMAIL));
        String mfaToken = startLogin();
        for (int i = 0; i < 5; i++) {
            completeLogin(mfaToken, "123456").andExpect(status().isUnauthorized());
        }
        completeLogin(mfaToken, totpCode(totp.secret(), 0)).andExpect(status().isUnauthorized());
    }

    @Test
    void recoveryCodesWorkExactlyOnce() throws Exception {
        Totp totp = enableTotp(newAccount(EMAIL));
        String code = totp.recoveryCodes().get(0);
        // Typed sloppily from paper: lowercase, no dash.
        completeLogin(startLogin(), code.replace("-", "").toLowerCase()).andExpect(status().isOk());
        completeLogin(startLogin(), code).andExpect(status().isUnauthorized());
        verify(email).sendSecurityNotice(eq(EMAIL), eq("A recovery code was used"), anyString());
    }

    @Test
    void passwordResetDoesNotRemoveTheSecondFactor() throws Exception {
        enableTotp(newAccount(EMAIL));
        mvc.perform(postJson("/api/v1/auth/forgot-password", Map.of("email", EMAIL))).andExpect(status().isOk());
        mvc.perform(postJson("/api/v1/auth/reset-password",
                        Map.of("token", resetTokenFor(EMAIL), "newPassword", "a-brand-new-passphrase")))
                .andExpect(status().isOk());
        login(EMAIL, "a-brand-new-passphrase").andExpect(jsonPath("$.mfaRequired").value(true));
    }

    @Test
    void sensitiveChangesRequireARecentReauthentication() throws Exception {
        Session session = newAccount(EMAIL);
        Totp totp = enableTotp(session);
        expireReauth(session);

        mvc.perform(as(session, post("/api/v1/users/me/mfa/totp/disable")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REAUTH_REQUIRED"));

        // With TOTP on, the password alone doesn't re-authenticate.
        mvc.perform(as(session, postJson("/api/v1/users/me/reauth", Map.of("password", PASSWORD))))
                .andExpect(status().isBadRequest());
        mvc.perform(as(session, postJson("/api/v1/users/me/reauth", Map.of("password", "wrong-one-entirely",
                        "code", totpCode(totp.secret(), 0)))))
                .andExpect(status().isBadRequest());
        mvc.perform(as(session, postJson("/api/v1/users/me/reauth",
                        Map.of("password", PASSWORD, "code", totpCode(totp.secret(), 1)))))
                .andExpect(status().isOk());

        mvc.perform(as(session, post("/api/v1/users/me/mfa/totp/disable"))).andExpect(status().isOk());
        login(EMAIL, PASSWORD).andExpect(jsonPath("$.accessToken").exists());
    }

    @Test
    void totpSecretsAreEncryptedAtRest() throws Exception {
        Session session = newAccount(EMAIL);
        Totp totp = enableTotp(session);
        String stored = jdbc.queryForObject("select totp_secret from users", String.class);
        assertThat(stored).startsWith("v1:").doesNotContain(totp.secret());
        // Moving the ciphertext to another account doesn't work: it is bound to its row.
        long other = newAccount("other@example.com").userId();
        jdbc.update("update users set totp_secret = ? where id = ?", stored, other);
        mvc.perform(postJson("/api/v1/auth/login", Map.of("email", "other@example.com", "password", PASSWORD)))
                .andExpect(status().isOk());
        String token = body(login("other@example.com", PASSWORD).andReturn()).get("mfaToken").asString();
        mvc.perform(postJson("/api/v1/auth/mfa", Map.of("mfaToken", token, "code", totpCode(totp.secret(), 0))))
                .andExpect(status().is5xxServerError());
    }

    @Test
    void changingThePasswordNeedsTheCodeAndKeepsOnlyThisSession() throws Exception {
        Session session = newAccount(EMAIL);
        Totp totp = enableTotp(session);
        Session other = session(completeLogin(startLogin(), totp.recoveryCodes().get(1)).andReturn());

        mvc.perform(as(session, postJson("/api/v1/users/me/change-password",
                        Map.of("currentPassword", PASSWORD, "newPassword", "another-long-passphrase"))))
                .andExpect(status().isBadRequest());
        mvc.perform(as(session, postJson("/api/v1/users/me/change-password",
                        Map.of("currentPassword", PASSWORD, "newPassword", "another-long-passphrase",
                                "code", totpCode(totp.secret(), 0)))))
                .andExpect(status().isOk());

        mvc.perform(as(session, get("/api/v1/users/me"))).andExpect(status().isOk());
        mvc.perform(as(other, get("/api/v1/users/me"))).andExpect(status().isUnauthorized());
    }
}
