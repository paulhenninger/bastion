package dev.bastion;

import dev.bastion.support.IntegrationTest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Sessions, email change, deletion and export, administration, and request hardening. */
class AccountAndAdminIntegrationTest extends IntegrationTest {

    private static final String EMAIL = "someone@example.com";

    // ------------------------------------------------------------- sessions

    @Test
    void usersCanSeeAndEndTheirSessions() throws Exception {
        Session first = newAccount(EMAIL);
        Session second = signIn(EMAIL, PASSWORD);

        String list = mvc.perform(as(second, get("/api/v1/users/me/sessions")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andReturn().getResponse().getContentAsString();
        assertThat(list).contains("\"current\":true");

        mvc.perform(as(second, post("/api/v1/users/me/sessions/revoke-others")))
                .andExpect(jsonPath("$.revoked").value(1));
        mvc.perform(as(first, get("/api/v1/users/me"))).andExpect(status().isUnauthorized());
        mvc.perform(as(second, get("/api/v1/users/me"))).andExpect(status().isOk());
    }

    @Test
    void aSessionIdFromAnotherAccountIsNotFound() throws Exception {
        Session mine = newAccount(EMAIL);
        Session theirs = newAccount("them@example.com");
        String theirId = body(mvc.perform(as(theirs, get("/api/v1/users/me/sessions"))).andReturn())
                .get(0).get("id").asString();
        mvc.perform(as(mine, delete("/api/v1/users/me/sessions/" + theirId))).andExpect(status().isNotFound());
        mvc.perform(as(theirs, get("/api/v1/users/me"))).andExpect(status().isOk());
    }

    @Test
    void signInFromANewDeviceAlertsTheOwner() throws Exception {
        newAccount(EMAIL);
        mvc.perform(postJson("/api/v1/auth/login", Map.of("email", EMAIL, "password", PASSWORD))
                        .header("User-Agent", "Totally different browser")
                        .with(r -> {
                            r.setRemoteAddr("203.0.113.9");
                            return r;
                        }))
                .andExpect(status().isOk());
        verify(email).sendNewSignInAlert(eq(EMAIL), eq("203.0.113.9"), eq("Totally different browser"), org.mockito.ArgumentMatchers.any());
    }

    // ---------------------------------------------------------- email change

    @Test
    void emailChangesOnlyWhenTheNewInboxConfirms() throws Exception {
        Session session = newAccount(EMAIL);
        mvc.perform(as(session, postJson("/api/v1/users/me/email", Map.of("newEmail", "moved@example.com"))))
                .andExpect(status().isOk());
        verify(email).sendSecurityNotice(eq(EMAIL), eq("Email change requested"), anyString());
        ArgumentCaptor<String> token = ArgumentCaptor.forClass(String.class);
        verify(email).sendEmailChangeConfirmation(eq("moved@example.com"), token.capture());

        login(EMAIL, PASSWORD).andExpect(status().isOk()); // nothing changed yet
        mvc.perform(postJson("/api/v1/auth/confirm-email-change", Map.of("token", token.getValue())))
                .andExpect(status().isOk());
        login("moved@example.com", PASSWORD).andExpect(status().isOk());
        login(EMAIL, PASSWORD).andExpect(status().isUnauthorized());
        mvc.perform(postJson("/api/v1/auth/confirm-email-change", Map.of("token", token.getValue())))
                .andExpect(status().isBadRequest());
    }

    @Test
    void emailChangeDoesNotRevealWhetherTheAddressIsTaken() throws Exception {
        newAccount("taken@example.com");
        Session session = newAccount(EMAIL);
        String taken = mvc.perform(as(session, postJson("/api/v1/users/me/email", Map.of("newEmail", "taken@example.com"))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(taken).contains("taken@example.com");
        verify(email, never()).sendEmailChangeConfirmation(eq("taken@example.com"), anyString());
    }

    // ------------------------------------------------------- deletion/export

    @Test
    void deletingTheAccountRequiresReauthAndRemovesEverything() throws Exception {
        Session session = newAccount(EMAIL);
        expireReauth(session);
        mvc.perform(as(session, delete("/api/v1/users/me"))).andExpect(status().isForbidden());
        mvc.perform(as(session, postJson("/api/v1/users/me/reauth", Map.of("password", PASSWORD))))
                .andExpect(status().isOk());
        mvc.perform(as(session, delete("/api/v1/users/me"))).andExpect(status().isOk());
        login(EMAIL, PASSWORD).andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("select count(*) from user_sessions", Integer.class)).isZero();
        // The security log outlives the account.
        await().atMost(Duration.ofSeconds(5)).until(() ->
                jdbc.queryForObject("select count(*) from security_events where type = 'ACCOUNT_DELETED'", Integer.class) == 1);
    }

    @Test
    void exportContainsTheAccountButNoSecrets() throws Exception {
        Session session = newAccount(EMAIL);
        enableTotp(session);
        String export = mvc.perform(as(session, get("/api/v1/users/me/export")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(export).contains(EMAIL).contains("sessions").doesNotContain("argon2").doesNotContain("v1:");
    }

    // --------------------------------------------------------------- admin

    private Session strongAdmin() throws Exception {
        Session admin = newAccount("admin@example.com");
        makeAdmin(admin.userId());
        enableTotp(admin); // enrolling a second factor upgrades the session
        return admin;
    }

    @Test
    void theAdminApiRequiresATwoFactorSession() throws Exception {
        Session admin = newAccount("admin@example.com");
        makeAdmin(admin.userId());
        mvc.perform(as(admin, get("/api/v1/admin/users")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ADMIN_MFA_REQUIRED"));
        enableTotp(admin);
        mvc.perform(as(admin, get("/api/v1/admin/users"))).andExpect(status().isOk());
    }

    @Test
    void lockingAUserEndsTheirSessionsImmediately() throws Exception {
        Session admin = strongAdmin();
        Session user = newAccount(EMAIL);
        mvc.perform(as(admin, put("/api/v1/admin/users/" + user.userId() + "/locked")
                        .contentType("application/json").content("{\"locked\":true}")))
                .andExpect(status().isOk());
        mvc.perform(as(user, get("/api/v1/users/me"))).andExpect(status().isUnauthorized());
        refresh(user.refreshCookie()).andExpect(status().isUnauthorized());
    }

    @Test
    void demotionTakesEffectOnTheNextRequest() throws Exception {
        Session admin = strongAdmin();
        Session other = newAccount("other.admin@example.com");
        makeAdmin(other.userId());
        enableTotp(other);
        mvc.perform(as(other, get("/api/v1/admin/users"))).andExpect(status().isOk());
        mvc.perform(as(admin, put("/api/v1/admin/users/" + other.userId() + "/role")
                        .contentType("application/json").content("{\"role\":\"USER\"}")))
                .andExpect(status().isOk());
        mvc.perform(as(other, get("/api/v1/admin/users"))).andExpect(status().isForbidden());
    }

    @Test
    void adminsCantActOnThemselvesAndMutationsNeedReauth() throws Exception {
        Session admin = strongAdmin();
        mvc.perform(as(admin, delete("/api/v1/admin/users/" + admin.userId()))).andExpect(status().isForbidden());
        Session user = newAccount(EMAIL);
        expireReauth(admin);
        mvc.perform(as(admin, delete("/api/v1/admin/users/" + user.userId())))
                .andExpect(jsonPath("$.code").value("REAUTH_REQUIRED"));
    }

    @Test
    void adminCanResetALostSecondFactor() throws Exception {
        Session admin = strongAdmin();
        Session user = newAccount(EMAIL);
        enableTotp(user);
        mvc.perform(as(admin, delete("/api/v1/admin/users/" + user.userId() + "/mfa"))).andExpect(status().isOk());
        login(EMAIL, PASSWORD).andExpect(jsonPath("$.accessToken").exists());
    }

    @Test
    void securityEventsAreRecordedAndSearchable() throws Exception {
        Session admin = strongAdmin();
        newAccount(EMAIL);
        login(EMAIL, "wrong-password-123");
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                mvc.perform(as(admin, get("/api/v1/admin/security-events").param("email", EMAIL)
                                .param("type", "SIGN_IN_FAILED")))
                        .andExpect(jsonPath("$.totalElements").value(1))
                        .andExpect(jsonPath("$.content[0].ip").value("127.0.0.1")));
    }

    @Test
    void closingSignupsIsEnforcedByTheServer() throws Exception {
        Session admin = strongAdmin();
        mvc.perform(as(admin, put("/api/v1/admin/settings").contentType("application/json")
                .content("{\"signupsOpen\":false}"))).andExpect(status().isOk());
        mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", "late@example.com", "password", PASSWORD)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("SIGNUPS_CLOSED"));
    }

    @Test
    void theBootstrapEmailBecomesTheFirstAdminOnlyWhenNoneExists() throws Exception {
        newAccount("boss@example.com"); // matches app.admin.bootstrap-email in the test profile
        assertThat(jdbc.queryForObject("select role from users where email = 'boss@example.com'", String.class))
                .isEqualTo("ADMIN");
    }

    // ----------------------------------------------------------- hardening

    @Test
    void malformedRequestsAre4xxNever500() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType("application/json").content("{not json"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/auth/login").contentType("text/plain").content("x"))
                .andExpect(status().isUnsupportedMediaType());
        mvc.perform(get("/api/v1/auth/login")).andExpect(status().isMethodNotAllowed());
        mvc.perform(postJson("/api/v1/auth/login", Map.of("email", "a@b.co")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void oversizedBodiesAreRefusedBeforeBeingRead() throws Exception {
        String huge = "x".repeat(70_000);
        mvc.perform(postJson("/api/v1/auth/login", Map.of("email", "a@example.com", "password", huge)))
                .andExpect(status().isContentTooLarge());
    }

    @Test
    void forgedOrForeignTokensAreRejected() throws Exception {
        Session session = newAccount(EMAIL);
        String[] parts = session.accessToken().split("\\.");
        String tampered = parts[0] + "." + parts[1].substring(0, parts[1].length() - 2) + "AA." + parts[2];
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized());
        String none = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes())
                + "." + parts[1] + ".";
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + none))
                .andExpect(status().isUnauthorized());
    }
}
