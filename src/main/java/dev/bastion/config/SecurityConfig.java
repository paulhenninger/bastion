package dev.bastion.config;

import dev.bastion.security.ClientInfo;
import dev.bastion.security.JwtAuthFilter;
import dev.bastion.security.RateLimitFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /** The API returns JSON only, so it may load nothing and be framed by no one. */
    private static final String API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    private final JwtAuthFilter jwtAuthFilter;
    private final RateLimitFilter rateLimitFilter;
    private final AppProperties props;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, RateLimitFilter rateLimitFilter, AppProperties props) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.rateLimitFilter = rateLimitFilter;
        this.props = props;
        ClientInfo.trustForwardedFor(props.security().trustForwardedFor());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF: the API authenticates with a Bearer token held in memory, which a
                // cross-site page can't attach. The one cookie (refresh) is SameSite=Strict,
                // scoped to /api/v1/auth, and its endpoints also demand a custom header that
                // forces a CORS preflight (see AuthController.requireClientHeader).
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                .requestCache(cache -> cache.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/**", "/error").permitAll()
                        // Only reachable on the management port (MANAGEMENT_PORT), which the
                        // bundled nginx never proxies. See docs/operations.md.
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(API_CSP))
                        .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                        .frameOptions(f -> f.deny())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(Duration.ofDays(365).toSeconds()))
                        .permissionsPolicyHeader(p -> p.policy(
                                "camera=(), microphone=(), geolocation=(), payment=(), usb=()")))
                .exceptionHandling(ex -> ex
                        // Unauthenticated → JSON 401 so the SPA's refresh logic can react.
                        .authenticationEntryPoint((req, res, e) ->
                                writeJson(res, HttpServletResponse.SC_UNAUTHORIZED, "Authentication required"))
                        // Authenticated but not allowed → 403, NOT 401. A 401 here would send
                        // a non-admin SPA user into the session-expiry refresh loop.
                        .accessDeniedHandler((req, res, e) ->
                                writeJson(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden")))
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    private static void writeJson(HttpServletResponse res, int status, String message) throws IOException {
        res.setStatus(status);
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.getWriter().write("{\"message\":\"" + message + "\"}");
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(props.security().corsOrigins().stream().filter(o -> !o.isBlank()).toList());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Bastion-Client", "X-Request-Id"));
        config.setExposedHeaders(List.of("X-Request-Id", "Retry-After"));
        config.setAllowCredentials(true); // the refresh cookie must survive cross-origin dev
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }

    /**
     * Argon2id for every new hash (OWASP's first choice: memory-hard, so GPU and ASIC
     * cracking of a stolen table is expensive). Parameters are OWASP's minimum
     * recommendation — m=19 MiB, t=2, p=1 — about 50 ms per hash on a modern core.
     *
     * <p>Hashes are stored with their algorithm prefix ({@code {argon2}...}), so the
     * algorithm can change again later without a migration: legacy BCrypt rows (with or
     * without a prefix) still verify, and AuthService re-hashes them with Argon2id at
     * the next successful sign-in.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        Argon2PasswordEncoder argon2 = new Argon2PasswordEncoder(16, 32, 1, 19_456, 2);
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);
        DelegatingPasswordEncoder encoder = new DelegatingPasswordEncoder("argon2", Map.of(
                "argon2", argon2,
                "bcrypt", bcrypt));
        // Rows written by Bastion 1.x are bare BCrypt with no prefix.
        encoder.setDefaultPasswordEncoderForMatches(bcrypt);
        return encoder;
    }

    // These filters run inside the security chain (above). As @Components, Boot would
    // also register them as plain servlet filters, running each twice and outside
    // the chain's ordering — switch that off.

    @Bean
    FilterRegistrationBean<JwtAuthFilter> jwtAuthFilterRegistration(JwtAuthFilter filter) {
        FilterRegistrationBean<JwtAuthFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(RateLimitFilter filter) {
        FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
