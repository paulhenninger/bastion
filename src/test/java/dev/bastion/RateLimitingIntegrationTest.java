package dev.bastion;

import dev.bastion.security.DeviceCookies;
import dev.bastion.support.IntegrationTest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Every limiter switched on. Each test uses its own client IP so the buckets don't collide. */
@TestPropertySource(properties = "app.security.rate-limits-enabled=true")
class RateLimitingIntegrationTest extends IntegrationTest {

    private org.springframework.test.web.servlet.ResultActions loginFrom(String ip, String address, String password,
                                                                         Cookie... cookies) throws Exception {
        var request = postJson("/api/v1/auth/login", Map.of("email", address, "password", password))
                .with(r -> {
                    r.setRemoteAddr(ip);
                    return r;
                });
        if (cookies.length > 0) {
            request.cookie(cookies);
        }
        return mvc.perform(request);
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
    void anAttackerSpendingTheAccountBudgetDoesntLockTheOwnerOutOfAKnownBrowser() throws Exception {
        newAccount("owner@example.com");
        MvcResult earlier = loginFrom("203.0.113.7", "owner@example.com", PASSWORD).andExpect(status().isOk()).andReturn();
        Cookie device = earlier.getResponse().getCookie(DeviceCookies.NAME);
        assertThat(device).isNotNull();
        assertThat(device.isHttpOnly()).isTrue();
        assertThat(device.getPath()).isEqualTo("/api/v1/auth");

        // Someone who knows the address burns the account's budget.
        for (int i = 1; i <= 10; i++) {
            loginFrom("198.51.100." + i, "owner@example.com", "guess-" + i + "-wrong").andExpect(status().isUnauthorized());
        }
        // New browsers are blocked — that is what stops spraying…
        loginFrom("203.0.113.8", "owner@example.com", PASSWORD).andExpect(status().isTooManyRequests());
        // …and a forged device cookie is just a new browser.
        loginFrom("203.0.113.8", "owner@example.com", PASSWORD, new Cookie(DeviceCookies.NAME, "1.forged.AAAA"))
                .andExpect(status().isTooManyRequests());
        // The owner's browser has signed in before: it gets in.
        loginFrom("203.0.113.7", "owner@example.com", PASSWORD, device).andExpect(status().isOk());

        // A known device is still budgeted, on its own.
        for (int i = 1; i <= 10; i++) {
            loginFrom("203.0.113.7", "owner@example.com", "typo-" + i + "-wrong", device).andExpect(status().isUnauthorized());
        }
        loginFrom("203.0.113.7", "owner@example.com", PASSWORD, device).andExpect(status().isTooManyRequests());
    }

    @Test
    void rejectedSignupsDontUseUpTheHourlySignupLimitButAreCappedThemselves() throws Exception {
        var tooShort = Map.of("email", "typist@example.com", "password", "short");
        for (int i = 0; i < 8; i++) {
            mvc.perform(postJson("/api/v1/auth/signup", tooShort).with(from("192.0.2.77"))).andExpect(status().isBadRequest());
        }
        // Five rejected attempts used to lock a person out of signing up for an hour.
        mvc.perform(postJson("/api/v1/auth/signup", Map.of("email", "typist@example.com", "password", PASSWORD))
                .with(from("192.0.2.77"))).andExpect(status().isCreated());

        for (int i = 0; i < 30; i++) {
            mvc.perform(postJson("/api/v1/auth/signup", tooShort).with(from("192.0.2.78")));
        }
        mvc.perform(postJson("/api/v1/auth/signup", tooShort).with(from("192.0.2.78")))
                .andExpect(status().isTooManyRequests());
    }

    private static org.springframework.test.web.servlet.request.RequestPostProcessor from(String ip) {
        return r -> {
            r.setRemoteAddr(ip);
            return r;
        };
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
