package dev.bastion.session;

import dev.bastion.user.Role;

import java.time.Instant;

/**
 * The signed-in caller, as resolved fresh from the database on every request:
 * the account and the session it is using. Controllers take it with
 * {@code @AuthenticationPrincipal AuthPrincipal me}.
 */
public record AuthPrincipal(
        Long userId,
        String email,
        Role role,
        Long sessionId,
        String sessionPublicId,
        boolean strongAuth,
        Instant reauthAt) {

    public boolean isAdmin() {
        return role == Role.ADMIN;
    }
}
