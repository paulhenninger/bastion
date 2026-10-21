package dev.bastion.security;

import dev.bastion.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Optional Cloudflare Turnstile CAPTCHA on the anonymous endpoints that send email
 * (signup, forgot-password, resend-verification). Rate limits bound a single
 * source; this raises the cost of every attempt from a botnet rotating IPs.
 *
 * <p><b>Off unless both keys are configured</b> — dev, tests and self-hosters need
 * no Cloudflare account.
 *
 * <p><b>Fails closed on a rejected token, open on an outage.</b> A token Cloudflare
 * actively rejects is a failed challenge. A timeout or error from Cloudflare itself
 * lets the request through: the CAPTCHA is spam control layered on rate limiting,
 * and a Cloudflare incident must not take down account creation.
 */
@Component
public class TurnstileVerifier {

    private static final Logger log = LoggerFactory.getLogger(TurnstileVerifier.class);
    private static final URI SITEVERIFY = URI.create("https://challenges.cloudflare.com/turnstile/v0/siteverify");
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    private final AppProperties.Turnstile config;
    private final JsonMapper json = JsonMapper.builder().build();

    public TurnstileVerifier(AppProperties props) {
        this.config = props.turnstile();
    }

    public boolean enabled() {
        return config.enabled();
    }

    public String siteKey() {
        return enabled() ? config.siteKey() : null;
    }

    /** True when the challenge passed, Turnstile is off, or Cloudflare couldn't be reached. */
    public boolean verify(String token, String clientIp) {
        if (!enabled()) {
            return true;
        }
        if (token == null || token.isBlank() || token.length() > 2048) {
            return false;
        }
        String form = "secret=" + enc(config.secretKey()) + "&response=" + enc(token)
                + (clientIp == null ? "" : "&remoteip=" + enc(clientIp));
        try {
            HttpRequest request = HttpRequest.newBuilder(SITEVERIFY)
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();
            HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode body = json.readTree(response.body());
            boolean ok = body.path("success").asBoolean(false);
            if (!ok) {
                log.info("Turnstile challenge rejected: {}", body.path("error-codes"));
            }
            return ok;
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            return true;
        } catch (Exception e) {
            log.error("Turnstile verification unavailable, allowing the request: {}", e.toString());
            return true;
        }
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
