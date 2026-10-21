package dev.bastion.support;

import dev.bastion.auth.AuthController;
import dev.bastion.email.EmailService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full-stack tests through MockMvc against H2. EmailService is mocked so tests can
 * read the tokens "from the inbox". Every test starts from empty tables.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public abstract class IntegrationTest {

    protected static final String PASSWORD = "correct-horse-battery-staple";

    @Autowired
    protected MockMvc mvc;
    @Autowired
    protected JdbcTemplate jdbc;
    @MockitoBean
    protected EmailService email;

    protected final JsonMapper json = JsonMapper.builder().build();

    @BeforeEach
    void cleanDatabase() {
        List<String> tables = jdbc.queryForList(
                "select table_name from information_schema.tables where table_schema = 'PUBLIC'", String.class);
        jdbc.execute("SET REFERENTIAL_INTEGRITY FALSE");
        tables.forEach(t -> jdbc.execute("TRUNCATE TABLE " + t + " RESTART IDENTITY"));
        jdbc.execute("SET REFERENTIAL_INTEGRITY TRUE");
        clearInvocations(email);
    }

    /** A signed-in client: the in-memory access token and the refresh cookie. */
    public record Session(String accessToken, Cookie refreshCookie, long userId) {
    }

    // ---------------------------------------------------------------- requests

    protected MockHttpServletRequestBuilder postJson(String path, Object body) {
        return post(path).contentType("application/json").content(json.writeValueAsString(body));
    }

    protected MockHttpServletRequestBuilder as(Session session, MockHttpServletRequestBuilder builder) {
        return builder.header("Authorization", "Bearer " + session.accessToken());
    }

    protected ResultActions refresh(Cookie cookie) throws Exception {
        return mvc.perform(post("/api/v1/auth/refresh")
                .header(AuthController.CLIENT_HEADER, "web")
                .cookie(cookie));
    }

    protected JsonNode body(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    protected Session session(MvcResult result) throws Exception {
        JsonNode node = body(result);
        Cookie cookie = result.getResponse().getCookie(AuthController.REFRESH_COOKIE);
        assertThat(cookie).as("refresh cookie").isNotNull();
        return new Session(node.get("accessToken").asString(), cookie, node.get("user").get("id").asLong());
    }

    // ------------------------------------------------------------- user setup

    /** Signs up and returns the token from the verification email. */
    protected String signup(String address, String password) throws Exception {
        clearInvocations(email);
        mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", address, "password", password)))
                .andExpect(status().isCreated());
        ArgumentCaptor<String> token = ArgumentCaptor.forClass(String.class);
        verify(email, atLeastOnce()).sendVerificationEmail(eq(address), token.capture());
        return token.getValue();
    }

    protected ResultActions verifyEmail(String token, String password) throws Exception {
        return mvc.perform(postJson("/api/v1/auth/verify-email", Map.of("token", token, "password", password)));
    }

    /** A verified account, signed in by its verification link. */
    protected Session newAccount(String address) throws Exception {
        String token = signup(address, PASSWORD);
        return session(verifyEmail(token, PASSWORD).andExpect(status().isOk()).andReturn());
    }

    protected ResultActions login(String address, String password) throws Exception {
        return mvc.perform(postJson("/api/v1/auth/login", Map.of("email", address, "password", password)));
    }

    protected Session signIn(String address, String password) throws Exception {
        return session(login(address, password).andExpect(status().isOk()).andReturn());
    }

    /** The token from the most recent password-reset email (sent asynchronously). */
    protected String resetTokenFor(String address) {
        ArgumentCaptor<String> token = ArgumentCaptor.forClass(String.class);
        verify(email, timeout(5000).atLeastOnce()).sendPasswordResetEmail(eq(address), token.capture(), org.mockito.ArgumentMatchers.any());
        return token.getValue();
    }

    protected void makeAdmin(long userId) {
        jdbc.update("update users set role = 'ADMIN' where id = ?", userId);
    }

    /** Pretends the session's last re-authentication was long ago. */
    protected void expireReauth(Session session) {
        jdbc.update("update user_sessions set reauth_at = ? where user_id = ?",
                java.sql.Timestamp.from(Instant.now().minusSeconds(3600)), session.userId());
    }

    // ------------------------------------------------------------------- TOTP

    public record Totp(String secret, List<String> recoveryCodes) {
    }

    /** Turns TOTP on for a freshly signed-in session (which counts as re-authenticated). */
    protected Totp enableTotp(Session session) throws Exception {
        JsonNode setup = body(mvc.perform(as(session, post("/api/v1/users/me/mfa/totp/setup")))
                .andExpect(status().isOk()).andReturn());
        String secret = setup.get("secret").asString();
        assertThat(setup.get("otpauthUri").asString()).startsWith("otpauth://totp/");
        JsonNode enabled = body(mvc.perform(as(session, postJson("/api/v1/users/me/mfa/totp/enable",
                        Map.of("code", totpCode(secret, 0)))))
                .andExpect(status().isOk()).andReturn());
        List<String> codes = new java.util.ArrayList<>();
        enabled.get("recoveryCodes").forEach(n -> codes.add(n.asString()));
        clearTotpReplayGuard(session.userId());
        return new Totp(secret, codes);
    }

    /** Lets the next test step reuse the current time step (tests run faster than 30 s). */
    protected void clearTotpReplayGuard(long userId) {
        jdbc.update("update users set totp_last_step = null where id = ?", userId);
    }

    /**
     * RFC 6238 code for "now + offsetSteps", computed independently of TotpService so
     * the tests check it against a second implementation, not against itself.
     */
    public static String totpCode(String base32Secret, int offsetSteps) {
        try {
            long step = Instant.now().getEpochSecond() / 30 + offsetSteps;
            byte[] counter = java.nio.ByteBuffer.allocate(8).putLong(step).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(base32(base32Secret), "HmacSHA1"));
            byte[] h = mac.doFinal(counter);
            int o = h[h.length - 1] & 0xf;
            int bin = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
            return String.format("%06d", bin % 1_000_000);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] base32(String s) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (char c : s.toCharArray()) {
            buffer = (buffer << 5) | alphabet.indexOf(c);
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }
}
