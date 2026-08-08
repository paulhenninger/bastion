package dev.bastion.security;

import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Resolves a Bearer access token to an authenticated principal. The user row is
 * re-read from the database on every request, so a lock or role change takes effect
 * on the target's next call — not when their JWT happens to expire.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public JwtAuthFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            Optional<Long> userId = jwtService.validate(header.substring(7));
            if (userId.isPresent()) {
                Optional<User> user = userRepository.findById(userId.get());
                if (user.isPresent() && user.get().isEnabled() && !user.get().isLocked()) {
                    var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + user.get().getRole().name()));
                    var auth = new UsernamePasswordAuthenticationToken(user.get(), null, authorities);
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            }
        }
        chain.doFilter(request, response);
    }
}
