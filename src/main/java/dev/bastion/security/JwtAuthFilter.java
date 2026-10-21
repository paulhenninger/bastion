package dev.bastion.security;

import dev.bastion.session.AuthPrincipal;
import dev.bastion.session.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Resolves a Bearer access token to an authenticated principal.
 *
 * <p>The signature proves the token was issued here; it does not prove the session is
 * still wanted. So the session row and its user are re-read on every request (one
 * indexed query): a sign-out, "sign out other devices", password reset, admin lock or
 * role change takes effect on the target's next call — not whenever their JWT expires.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final String MDC_USER = "userId";

    private final JwtService jwtService;
    private final SessionService sessions;

    public JwtAuthFilter(JwtService jwtService, SessionService sessions) {
        this.jwtService = jwtService;
        this.sessions = sessions;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ") && header.length() < 4096) {
            jwtService.validate(header.substring(7).trim())
                    .flatMap(claims -> sessions.resolve(claims.userId(), claims.sessionId()))
                    .ifPresent(this::authenticate);
        }
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_USER);
        }
    }

    private void authenticate(AuthPrincipal principal) {
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + principal.role().name()));
        var auth = UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(auth);
        MDC.put(MDC_USER, String.valueOf(principal.userId()));
    }
}
