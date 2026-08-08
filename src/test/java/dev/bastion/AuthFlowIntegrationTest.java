package dev.bastion;

import dev.bastion.email.EmailService;
import dev.bastion.user.UserRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The whole happy path and its guard rails, end to end through MockMvc:
 * signup → verify → login → me → refresh rotation → logout.
 * EmailService is mocked to capture the raw tokens the way an inbox would.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@org.springframework.transaction.annotation.Transactional
class AuthFlowIntegrationTest {

    private static final String EMAIL = "new.user@example.com";
    private static final String PASSWORD = "correct-horse-battery";

    @Autowired
    private MockMvc mvc;
    @Autowired
    private UserRepository users;

    private final ObjectMapper json = JsonMapper.builder().build();
    @MockitoBean
    private EmailService emailService;

    @BeforeEach
    void cleanUp() {
        users.deleteAll();
    }

    @Test
    void fullSignupVerifyLoginRefreshFlow() throws Exception {
        // 1. Signup fires a verification email; the account can't log in yet.
        mvc.perform(post("/api/v1/auth/signup")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of(
                                "email", EMAIL, "password", PASSWORD, "name", "New User"))))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isForbidden());

        // 2. Verify with the emailed token → authenticated session.
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendVerificationEmail(eq(EMAIL), tokenCaptor.capture());

        MvcResult verified = mvc.perform(get("/api/v1/auth/verify-email")
                        .param("token", tokenCaptor.getValue()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();

        // A verification link is single-use.
        mvc.perform(get("/api/v1/auth/verify-email").param("token", tokenCaptor.getValue()))
                .andExpect(status().isBadRequest());

        // 3. Login now works and sets the refresh cookie.
        MvcResult login = mvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.email").value(EMAIL))
                .andReturn();

        Cookie refreshCookie = login.getResponse().getCookie("bastion_refresh");
        assertThat(refreshCookie).isNotNull();
        assertThat(refreshCookie.isHttpOnly()).isTrue();

        String accessToken = json.readTree(login.getResponse().getContentAsString())
                .get("accessToken").asString();

        // 4. The access token opens protected endpoints.
        mvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(EMAIL));

        // …but not the admin tree (403, not 401 — the SPA must not enter its refresh loop).
        mvc.perform(get("/api/v1/admin/users")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());

        // 5. Refresh rotates the cookie.
        MvcResult refreshed = mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();
        Cookie rotated = refreshed.getResponse().getCookie("bastion_refresh");
        assertThat(rotated).isNotNull();
        assertThat(rotated.getValue()).isNotEqualTo(refreshCookie.getValue());

        // The consumed cookie no longer refreshes.
        mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie))
                .andExpect(status().isUnauthorized());

        // 6. Logout revokes and clears; the rotated cookie is dead afterwards.
        mvc.perform(post("/api/v1/auth/logout").cookie(rotated))
                .andExpect(status().isOk());
        mvc.perform(post("/api/v1/auth/refresh").cookie(rotated))
                .andExpect(status().isUnauthorized());

        assertThat(verified.getResponse().getCookie("bastion_refresh")).isNotNull();
    }

    @Test
    void wrongPasswordAndUnknownEmailLookIdentical() throws Exception {
        mvc.perform(post("/api/v1/auth/signup")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isCreated());

        String wrongPassword = mvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", "wrong-password"))))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        String unknownEmail = mvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", "nobody@example.com", "password", "whatever-pass"))))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertThat(wrongPassword).isEqualTo(unknownEmail);
    }

    @Test
    void signupForAnExistingVerifiedAccountRepliesGenerically() throws Exception {
        mvc.perform(post("/api/v1/auth/signup")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isCreated());
        users.findByEmail(EMAIL).ifPresent(u -> {
            u.setEnabled(true);
            users.save(u);
        });

        // Same 201, no new account, and no way to take over the existing one.
        mvc.perform(post("/api/v1/auth/signup")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", "attacker-password"))))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", "attacker-password"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void passwordResetFlowEndsEverySession() throws Exception {
        // Arrange: a verified account with a live session.
        mvc.perform(post("/api/v1/auth/signup")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isCreated());
        users.findByEmail(EMAIL).ifPresent(u -> {
            u.setEnabled(true);
            users.save(u);
        });
        MvcResult login = mvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isOk())
                .andReturn();
        Cookie session = login.getResponse().getCookie("bastion_refresh");

        // Act: forgot → reset with the emailed token.
        mvc.perform(post("/api/v1/auth/forgot-password")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL))))
                .andExpect(status().isOk());

        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendPasswordResetEmail(eq(EMAIL), tokenCaptor.capture());

        mvc.perform(post("/api/v1/auth/reset-password")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of(
                                "token", tokenCaptor.getValue(), "newPassword", "brand-new-password"))))
                .andExpect(status().isOk());

        // Assert: old password dead, new one works, old session revoked, token single-use.
        mvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", "brand-new-password"))))
                .andExpect(status().isOk());
        mvc.perform(post("/api/v1/auth/refresh").cookie(session))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/reset-password")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of(
                                "token", tokenCaptor.getValue(), "newPassword", "another-password"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void forgotPasswordForUnknownEmailStaysGeneric() throws Exception {
        mvc.perform(post("/api/v1/auth/forgot-password")
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of("email", "nobody@example.com"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").isNotEmpty());
        verify(emailService, org.mockito.Mockito.never())
                .sendPasswordResetEmail(anyString(), anyString());
    }
}
