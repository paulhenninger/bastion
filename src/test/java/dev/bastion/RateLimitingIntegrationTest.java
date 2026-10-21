package dev.bastion;

import dev.bastion.support.IntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Every limiter switched on. Each test uses its own client IP so the buckets don't collide. */
@TestPropertySource(properties = "app.security.rate-limits-enabled=true")
class RateLimitingIntegrationTest extends IntegrationTest {

    private org.springframework.test.web.servlet.ResultActions loginFrom(String ip, String address, String password)
            throws Exception {
        return mvc.perform(postJson("/api/v1/auth/login", Map.of("email", address, "password", password))
                .with(r -> {
                    r.setRemoteAddr(ip);
                    return r;
                }));
    }

    @Test
    void passwordSprayingOneAccountFromManyIpsIsThrottledPerAccount() throws Exception {
        newAccount("target@example.com");
        for (int i = 1; i <= 10; i++) {
            loginFrom("198.51.100." + i, "target@example.com", "guess-" + i + "-wrong").andExpect(status().isUnauthorized());
        }
        // Eleventh guess from yet another IP: the account's budget is spent — even for the right password.
        loginFrom("198.51.100.99", "target@example.com", PASSWORD)
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("RATE_LIMITED"));
        // An unknown address gets the same treatment, so a 429 says nothing about registration.
        for (int i = 1; i <= 10; i++) {
            loginFrom("198.51.100." + (20 + i), "ghost@example.com", "guess-" + i + "-wrong").andExpect(status().isUnauthorized());
        }
        loginFrom("198.51.100.98", "ghost@example.com", "whatever-password").andExpect(status().isTooManyRequests());
    }

    @Test
    void oneIpHammeringLoginIsThrottledPerIp() throws Exception {
        for (int i = 0; i < 20; i++) {
            loginFrom("192.0.2.50", "user" + i + "@example.com", "wrong-password-x").andExpect(status().isUnauthorized());
        }
        loginFrom("192.0.2.50", "user99@example.com", "wrong-password-x")
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    void reauthPasswordGuessesAreBudgetedPerAccount() throws Exception {
        Session session = newAccount("victim@example.com");
        for (int i = 0; i < 5; i++) {
            mvc.perform(as(session, postJson("/api/v1/users/me/reauth", Map.of("password", "guess-" + i + "-wrong"))))
                    .andExpect(status().isBadRequest());
        }
        // A stolen access token can't grind the password through re-authentication.
        mvc.perform(as(session, postJson("/api/v1/users/me/reauth", Map.of("password", PASSWORD))))
                .andExpect(status().isTooManyRequests());
    }
}
