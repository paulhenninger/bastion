package dev.bastion;

import dev.bastion.auth.AuthController;
import dev.bastion.support.IntegrationTest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The account lifecycle end to end, and the guarantees each step makes. */
class AuthFlowIntegrationTest extends IntegrationTest {

    private static final String EMAIL = "new.user@example.com";

    @Test
    void signupVerifyLoginRefreshLogout() throws Exception {
        String token = signup(EMAIL, PASSWORD);

        // Unverified accounts can't sign in — and say so only after the right password.
        login(EMAIL, PASSWORD).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("EMAIL_NOT_VERIFIED"));

        // Verifying needs the link AND the password chosen at signup.
        verifyEmail(token, "not-the-signup-password").andExpect(status().isBadRequest());
        MvcResult verified = verifyEmail(token, PASSWORD).andExpect(status().isOk()).andReturn();
        Cookie cookie = verified.getResponse().getCookie(AuthController.REFRESH_COOKIE);
        assertThat(cookie).isNotNull();
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(verified.getResponse().getHeader("Set-Cookie")).contains("SameSite=Strict").contains("Path=/api/v1/auth");
        assertThat(verified.getResponse().getHeader("Cache-Control")).contains("no-store");

        // A verification link is single-use.
        verifyEmail(token, PASSWORD).andExpect(status().isBadRequest());

        Session session = signIn(EMAIL, PASSWORD);
        mvc.perform(as(session, get("/api/v1/users/me")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(EMAIL));
        // Not admin: 403, never 401 (the SPA must not enter its refresh loop).
        mvc.perform(as(session, get("/api/v1/admin/users"))).andExpect(status().isForbidden());

        // Refresh rotates the cookie; the consumed one is dead.
        MvcResult refreshed = refresh(session.refreshCookie()).andExpect(status().isOk()).andReturn();
        Cookie rotated = refreshed.getResponse().getCookie(AuthController.REFRESH_COOKIE);
        assertThat(rotated.getValue()).isNotEqualTo(session.refreshCookie().getValue());
        refresh(session.refreshCookie()).andExpect(status().isUnauthorized());

        // Logout ends the session for the cookie AND the access token — immediately,
        // not when the JWT expires.
        mvc.perform(post("/api/v1/auth/logout").header(AuthController.CLIENT_HEADER, "web").cookie(rotated))
                .andExpect(status().isOk());
        refresh(rotated).andExpect(status().isUnauthorized());
        mvc.perform(as(session, get("/api/v1/users/me"))).andExpect(status().isUnauthorized());
    }

    @Test
    void cookieEndpointsRequireTheClientHeader() throws Exception {
        Session session = newAccount(EMAIL);
        // A cross-site form can post a cookie but can't add a custom header.
        mvc.perform(post("/api/v1/auth/refresh").cookie(session.refreshCookie()))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/auth/logout").cookie(session.refreshCookie()))
                .andExpect(status().isForbidden());
    }

    @Test
    void wrongPasswordAndUnknownEmailLookIdentical() throws Exception {
        newAccount(EMAIL);
        String wrongPassword = login(EMAIL, "wrong-password-123").andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String unknownEmail = login("nobody@example.com", "wrong-password-123").andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        assertThat(wrongPassword).isEqualTo(unknownEmail);
    }

    @Test
    void signupForAnExistingAccountRepliesGenericallyAndChangesNothing() throws Exception {
        newAccount(EMAIL);
        String reply = mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", EMAIL, "password", "attacker-password-1")))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String fresh = mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", "fresh@example.com", "password", PASSWORD)))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        assertThat(reply).isEqualTo(fresh);
        verify(email).sendExistingAccountNotice(EMAIL);
        login(EMAIL, "attacker-password-1").andExpect(status().isUnauthorized());
        login(EMAIL, PASSWORD).andExpect(status().isOk());
    }

    /**
     * Account pre-hijacking: the attacker registers the victim's address first, with a
     * password they know. However the victim's signup and the emails interleave, the
     * account that goes live must carry the victim's password and not the attacker's.
     */
    @Test
    void preRegisteringSomeoneElsesAddressGainsNothing() throws Exception {
        String attackerToken = signup(EMAIL, "attacker-knows-this-1");
        String victimToken = signup(EMAIL, PASSWORD);

        // The victim clicks either email — even the attacker-triggered one — and types their password.
        verifyEmail(attackerToken, PASSWORD).andExpect(status().isOk());
        assertThat(attackerToken).isNotEqualTo(victimToken);

        login(EMAIL, "attacker-knows-this-1").andExpect(status().isUnauthorized());
        login(EMAIL, PASSWORD).andExpect(status().isOk());
        // Every other pending link died with the verification.
        verifyEmail(victimToken, PASSWORD).andExpect(status().isBadRequest());
    }

    @Test
    void weakAndAccountNamePasswordsAreRefused() throws Exception {
        mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", EMAIL, "password", "short")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Password must be at least 12 characters"));
        mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", EMAIL, "password", "new.user@example.com!")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Password must not contain your email address"));
        // 73+ bytes used to crash BCrypt with a 500; Argon2 has no such limit.
        String longPassword = "é".repeat(60);
        mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", EMAIL, "password", longPassword)))
                .andExpect(status().isCreated());
    }

    @Test
    void malformedAddressesAreRefusedWithAReason() throws Exception {
        mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", "paul@gmail", "password", PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fields.email").value(org.hamcrest.Matchers.containsString("top-level domain")));
        mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", "someone@mailinator.com", "password", PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Disposable")));
    }

    @Test
    void passwordResetEndsEverySessionAndLinksAreSingleUse() throws Exception {
        Session session = newAccount(EMAIL);

        mvc.perform(postJson("/api/v1/auth/forgot-password", Map.of("email", EMAIL))).andExpect(status().isOk());
        String first = resetTokenFor(EMAIL);
        mvc.perform(postJson("/api/v1/auth/forgot-password", Map.of("email", EMAIL))).andExpect(status().isOk());
        String second = awaitNewResetToken(first);

        // Only the newest link works.
        mvc.perform(postJson("/api/v1/auth/reset-password", Map.of("token", first, "newPassword", "brand-new-password-1")))
                .andExpect(status().isBadRequest());
        mvc.perform(postJson("/api/v1/auth/reset-password", Map.of("token", second, "newPassword", "brand-new-password-1")))
                .andExpect(status().isOk());

        login(EMAIL, PASSWORD).andExpect(status().isUnauthorized());
        login(EMAIL, "brand-new-password-1").andExpect(status().isOk());
        refresh(session.refreshCookie()).andExpect(status().isUnauthorized());
        mvc.perform(as(session, get("/api/v1/users/me"))).andExpect(status().isUnauthorized());
        mvc.perform(postJson("/api/v1/auth/reset-password", Map.of("token", second, "newPassword", "another-password-1")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void forgotPasswordForUnknownEmailStaysGeneric() throws Exception {
        newAccount(EMAIL);
        String known = mvc.perform(postJson("/api/v1/auth/forgot-password", Map.of("email", EMAIL)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String unknown = mvc.perform(postJson("/api/v1/auth/forgot-password", Map.of("email", "nobody@example.com")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(known).isEqualTo(unknown);
        verify(email, after(500).never()).sendPasswordResetEmail(eq("nobody@example.com"), anyString(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void refreshTokenReplayRevokesEverySession() throws Exception {
        newAccount(EMAIL);
        Session laptop = signIn(EMAIL, PASSWORD);
        Session phone = signIn(EMAIL, PASSWORD);

        refresh(laptop.refreshCookie()).andExpect(status().isOk());
        // Push the rotation outside the two-tab grace window, then replay the old cookie.
        jdbc.update("update refresh_tokens set revoked_at = ? where revoked_at is not null",
                Timestamp.from(Instant.now().minusSeconds(120)));
        refresh(laptop.refreshCookie()).andExpect(status().isUnauthorized());

        // Theft assumed: every session for the account is gone, access tokens included.
        refresh(phone.refreshCookie()).andExpect(status().isUnauthorized());
        mvc.perform(as(phone, get("/api/v1/users/me"))).andExpect(status().isUnauthorized());
        verify(email).sendSecurityNotice(eq(EMAIL), eq("Suspicious session activity"), anyString());
    }

    @Test
    void sessionsEndAtTheirAbsoluteExpiryHoweverActive() throws Exception {
        Session session = newAccount(EMAIL);
        jdbc.update("update user_sessions set expires_at = ?", Timestamp.from(Instant.now().minusSeconds(1)));
        refresh(session.refreshCookie()).andExpect(status().isUnauthorized());
        mvc.perform(as(session, get("/api/v1/users/me"))).andExpect(status().isUnauthorized());
    }

    @Test
    void lockedAccountsAreRefusedOnlyAfterTheRightPassword() throws Exception {
        newAccount(EMAIL);
        jdbc.update("update users set locked = true");
        login(EMAIL, "wrong-password-123").andExpect(status().isUnauthorized());
        login(EMAIL, PASSWORD).andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
    }

    @Test
    void legacyBcryptHashesStillWorkAndAreUpgradedToArgon2() throws Exception {
        newAccount(EMAIL);
        String legacy = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode(PASSWORD);
        jdbc.update("update users set password_hash = ?", legacy);
        login(EMAIL, PASSWORD).andExpect(status().isOk());
        assertThat(jdbc.queryForObject("select password_hash from users", String.class)).startsWith("{argon2}");
    }

    @Test
    void accessTokensCarryNoPersonalData() throws Exception {
        Session session = newAccount(EMAIL);
        String payload = new String(java.util.Base64.getUrlDecoder().decode(session.accessToken().split("\\.")[1]));
        assertThat(payload).doesNotContain(EMAIL).contains("\"sid\"").contains("\"aud\"");
    }

    @Test
    void apiResponsesCarrySecurityHeaders() throws Exception {
        mvc.perform(get("/api/v1/auth/config"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("default-src 'none'")))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().exists("X-Request-Id"))
                .andExpect(jsonPath("$.passwordMinLength").value(12));
    }

    private String awaitNewResetToken(String previous) {
        org.awaitility.Awaitility.await().atMost(java.time.Duration.ofSeconds(5)).until(() -> {
            org.mockito.ArgumentCaptor<String> captor = org.mockito.ArgumentCaptor.forClass(String.class);
            verify(email, org.mockito.Mockito.atLeastOnce()).sendPasswordResetEmail(eq(EMAIL), captor.capture(), org.mockito.ArgumentMatchers.any());
            return !captor.getValue().equals(previous);
        });
        return resetTokenFor(EMAIL);
    }
}
