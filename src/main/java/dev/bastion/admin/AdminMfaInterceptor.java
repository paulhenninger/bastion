package dev.bastion.admin;

import dev.bastion.common.ApiException;
import dev.bastion.config.AppProperties;
import dev.bastion.session.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Administrators must have signed in with two factors (password + authenticator code,
 * a recovery code, or a passkey) to use the admin API. A stolen or guessed admin
 * password alone then reaches nothing administrative.
 *
 * <p>Applied after Spring Security has already required ROLE_ADMIN. Answers 403 with
 * code {@code ADMIN_MFA_REQUIRED} so the SPA can explain what to do. Disable with
 * {@code ADMIN_REQUIRES_MFA=false} (not recommended).
 */
@Component
class AdminMfaInterceptor implements HandlerInterceptor {

    private final boolean required;

    AdminMfaInterceptor(AppProperties props) {
        this.required = props.security().adminRequiresMfa();
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!required) {
            return true;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AuthPrincipal me && me.strongAuth()) {
            return true;
        }
        throw new ApiException(HttpStatus.FORBIDDEN,
                "Administrators must sign in with two-factor authentication or a passkey. "
                        + "Set one up in your account settings, then sign in again.",
                ApiException.ADMIN_MFA_REQUIRED);
    }
}
