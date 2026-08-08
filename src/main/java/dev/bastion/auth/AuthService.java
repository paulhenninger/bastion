package dev.bastion.auth;

import dev.bastion.auth.dto.AuthDtos.SignupRequest;
import dev.bastion.common.ApiException;
import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailService;
import dev.bastion.security.JwtService;
import dev.bastion.security.Tokens;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

/**
 * Signup, verification, login and password recovery.
 *
 * <p>The recovery endpoints are enumeration-safe on purpose: forgot-password and
 * resend-verification reply identically whether or not the address is registered,
 * so they cannot be used to probe which emails have accounts.
 */
@Service
public class AuthService {

    /** A real BCrypt hash of random material — burned on logins for unknown emails so
     *  the response time doesn't reveal whether the account exists. */
    private static final String TIMING_DUMMY_HASH =
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    private final UserRepository users;
    private final EmailVerificationTokenRepository verificationTokens;
    private final PasswordResetTokenRepository resetTokens;
    private final RefreshTokenService refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final AppProperties props;

    public AuthService(UserRepository users,
                       EmailVerificationTokenRepository verificationTokens,
                       PasswordResetTokenRepository resetTokens,
                       RefreshTokenService refreshTokens,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       EmailService emailService,
                       AppProperties props) {
        this.users = users;
        this.verificationTokens = verificationTokens;
        this.resetTokens = resetTokens;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.emailService = emailService;
        this.props = props;
    }

    // ------------------------------------------------------------------ signup

    @Transactional
    public void signup(SignupRequest request) {
        String email = normalize(request.email());
        Optional<User> existing = users.findByEmail(email);

        if (existing.isPresent()) {
            if (!existing.get().isEnabled()) {
                // Unverified re-signup: refresh their verification email rather than
                // erroring — the common case is "I never got the first one".
                sendVerification(existing.get());
            }
            // Verified account: reply exactly like a successful signup. An attacker
            // learns nothing; the legitimate owner still holds the account.
            return;
        }

        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setName(request.name() == null ? null : request.name().trim());
        users.save(user);
        sendVerification(user);
    }

    @Transactional
    public void resendVerification(String rawEmail) {
        users.findByEmail(normalize(rawEmail))
                .filter(u -> !u.isEnabled())
                .ifPresent(this::sendVerification);
        // Always fall through silently — generic reply regardless.
    }

    private void sendVerification(User user) {
        String raw = Tokens.newOpaqueToken();
        EmailVerificationToken token = new EmailVerificationToken();
        token.setUser(user);
        token.setTokenHash(Tokens.sha256(raw));
        token.setExpiresAt(Instant.now().plus(Duration.ofHours(props.verificationTokenHours())));
        verificationTokens.save(token);
        emailService.sendVerificationEmail(user.getEmail(), raw);
    }

    @Transactional
    public Session verifyEmail(String rawToken) {
        EmailVerificationToken token = verificationTokens.findByTokenHash(Tokens.sha256(rawToken))
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST,
                        "This verification link is invalid or has expired"));
        if (token.getUsedAt() != null || token.getExpiresAt().isBefore(Instant.now())) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "This verification link is invalid or has expired");
        }
        token.setUsedAt(Instant.now());
        verificationTokens.save(token);

        User user = token.getUser();
        user.setEnabled(true);
        users.save(user);
        return issueSession(user);
    }

    // ------------------------------------------------------------------- login

    @Transactional
    public Session login(String rawEmail, String password) {
        Optional<User> found = users.findByEmail(normalize(rawEmail));

        // Constant-shape verification: always run one BCrypt comparison.
        String hash = found.map(User::getPasswordHash).orElse(TIMING_DUMMY_HASH);
        boolean passwordOk = passwordEncoder.matches(password, hash);

        if (found.isEmpty() || !passwordOk) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }
        User user = found.get();
        // These checks run AFTER the password check on purpose: failing earlier would
        // confirm the account exists to someone who hasn't proven they own it.
        if (!user.isEnabled()) {
            throw new ApiException(HttpStatus.FORBIDDEN,
                    "Email address not verified. Check your inbox or request a new link.");
        }
        if (user.isLocked()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "This account has been locked");
        }
        return issueSession(user);
    }

    @Transactional
    public Optional<Session> refresh(String rawRefreshToken) {
        return refreshTokens.rotate(rawRefreshToken)
                .filter(r -> r.user().isEnabled() && !r.user().isLocked())
                .map(r -> new Session(jwtService.issueAccessToken(r.user()), r.newRawToken(), r.user()));
    }

    public void logout(String rawRefreshToken) {
        refreshTokens.revoke(rawRefreshToken);
    }

    // -------------------------------------------------------- password recovery

    @Transactional
    public void forgotPassword(String rawEmail) {
        users.findByEmail(normalize(rawEmail))
                .filter(User::isEnabled)
                .ifPresent(user -> {
                    String raw = Tokens.newOpaqueToken();
                    PasswordResetToken token = new PasswordResetToken();
                    token.setUser(user);
                    token.setTokenHash(Tokens.sha256(raw));
                    token.setExpiresAt(Instant.now().plus(Duration.ofMinutes(props.resetTokenMinutes())));
                    resetTokens.save(token);
                    emailService.sendPasswordResetEmail(user.getEmail(), raw);
                });
        // Generic reply either way — see class comment.
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        PasswordResetToken token = resetTokens.findByTokenHash(Tokens.sha256(rawToken))
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST,
                        "This reset link is invalid or has expired"));
        if (token.getUsedAt() != null || token.getExpiresAt().isBefore(Instant.now())) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "This reset link is invalid or has expired");
        }
        token.setUsedAt(Instant.now());
        resetTokens.save(token);

        User user = token.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        users.save(user);
        // A reset means the old credential may be compromised: end every session.
        refreshTokens.revokeAllForUser(user.getId());
        emailService.sendPasswordChangedNotice(user.getEmail());
    }

    // ----------------------------------------------------------------- helpers

    private Session issueSession(User user) {
        user.setLastLoginAt(Instant.now());
        users.save(user);
        return new Session(jwtService.issueAccessToken(user), refreshTokens.issue(user), user);
    }

    private static String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    /** A freshly authenticated session: short-lived JWT + the raw refresh token for the cookie. */
    public record Session(String accessToken, String refreshToken, User user) {
    }
}
