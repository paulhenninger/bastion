package dev.bastion.security;

import dev.bastion.config.AppProperties;
import dev.bastion.user.User;
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
 */
@Service
public class JwtService {

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

    public String issueAccessToken(User user) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(user.getId()))
                .claim("email", user.getEmail())
                .claim("role", user.getRole().name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTtl)))
                .signWith(key)
                .compact();
    }

    /** Returns the user id from a valid, unexpired token; empty otherwise. */
    public Optional<Long> validate(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return Optional.of(Long.parseLong(claims.getSubject()));
        } catch (JwtException | NumberFormatException e) {
            return Optional.empty();
        }
    }
}
