package dev.bastion.security;

import dev.bastion.config.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

/**
 * Issues and validates the short-lived HS256 access token. Fails fast at startup if
 * the signing key is missing, not valid base64, or under 256 bits — a weak or
 * defaulted JWT secret is not a configuration this app will run with.
 *
 * <p>The token carries only identifiers: the user id ({@code sub}) and the session it
 * belongs to ({@code sid}). No email, no role: authorisation is decided from the
 * database on every request (see JwtAuthFilter), so a stale claim can never grant
 * anything. Issuer and audience are pinned and checked, so a token minted by another
 * service that happens to share the key is still refused.
 *
 * <p>Rotating {@code JWT_SECRET} is safe at any time: outstanding access tokens stop
 * validating, clients refresh with their cookie, and nobody is signed out.
 */
@Service
public class JwtService {

    static final String ISSUER = "bastion";
    static final String AUDIENCE = "bastion-api";
    private static final long CLOCK_SKEW_SECONDS = 30;

    private final SecretKey key;
    private final Duration accessTtl;

    public JwtService(AppProperties props) {
        if (props.jwtSecret() == null || props.jwtSecret().isBlank()) {
            throw new IllegalStateException(
                    "JWT_SECRET is required. Generate one with: openssl rand -base64 32");
        }
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(props.jwtSecret().trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("JWT_SECRET is not valid base64", e);
        }
        if (bytes.length < 32) {
            throw new IllegalStateException(
                    "JWT_SECRET must be at least 256 bits (32 bytes) of decoded key material");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
        this.accessTtl = Duration.ofMinutes(props.accessTokenMinutes());
    }

    public String issueAccessToken(Long userId, String sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .subject(String.valueOf(userId))
                .claim("sid", sessionId)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTtl)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public long accessTokenSeconds() {
        return accessTtl.toSeconds();
    }

    /** The user and session from a valid, unexpired token; empty otherwise. */
    public Optional<AccessClaims> validate(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(ISSUER)
                    .requireAudience(AUDIENCE)
                    .clockSkewSeconds(CLOCK_SKEW_SECONDS)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String sid = claims.get("sid", String.class);
            if (sid == null || sid.isBlank()) {
                return Optional.empty();
            }
            return Optional.of(new AccessClaims(Long.parseLong(claims.getSubject()), sid));
        } catch (JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public record AccessClaims(Long userId, String sessionId) {
    }
}
