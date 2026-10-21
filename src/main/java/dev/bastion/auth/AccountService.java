package dev.bastion.auth;

import dev.bastion.audit.SecurityEvent;
import dev.bastion.audit.SecurityEventRepository;
import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.common.ApiException;
import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailAddress;
import dev.bastion.email.EmailDeliverability;
import dev.bastion.email.EmailService;
import dev.bastion.mfa.MfaService;
import dev.bastion.passkey.PasskeyService;
import dev.bastion.security.PasswordPolicy;
import dev.bastion.security.Tokens;
import dev.bastion.session.AuthPrincipal;
import dev.bastion.session.ReauthService;
import dev.bastion.session.SessionService;
import dev.bastion.user.Role;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Self-service changes to an account's credentials and existence. Every one of them
 * proves who is at the keyboard first — the current password (+ code) for a password
 * change, a recent re-authentication for the rest — and tells the owner afterwards.
 */
@Service
public class AccountService {

    private static final String CREATED_AT = "createdAt";

    private final UserRepository users;
    private final PasswordResetTokenRepository resetTokens;
    private final EmailChangeTokenRepository emailChangeTokens;
    private final SecurityEventRepository eventRepository;
    private final SessionService sessions;
    private final ReauthService reauth;
    private final MfaService mfa;
    private final PasskeyService passkeys;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final EmailDeliverability deliverability;
    private final EmailService email;
    private final SecurityEvents events;
    private final AppProperties props;
    private final TransactionTemplate tx;

    public AccountService(UserRepository users, PasswordResetTokenRepository resetTokens,
                          EmailChangeTokenRepository emailChangeTokens, SecurityEventRepository eventRepository,
                          SessionService sessions, ReauthService reauth, MfaService mfa, PasskeyService passkeys,
                          PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy,
                          EmailDeliverability deliverability, EmailService email, SecurityEvents events,
                          AppProperties props, PlatformTransactionManager transactionManager) {
        this.users = users;
        this.resetTokens = resetTokens;
        this.emailChangeTokens = emailChangeTokens;
        this.eventRepository = eventRepository;
        this.sessions = sessions;
        this.reauth = reauth;
        this.mfa = mfa;
        this.passkeys = passkeys;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.deliverability = deliverability;
        this.email = email;
        this.events = events;
        this.props = props;
        this.tx = new TransactionTemplate(transactionManager);
    }

    /**
     * Changes the password. Proves the current password (and, with TOTP on, a code), then
     * ends every <em>other</em> session — whoever else might have had the old password is
     * out — while the session that made the change carries on.
     */
    public void changePassword(AuthPrincipal me, String currentPassword, String newPassword, String code) {
        passwordPolicy.check(newPassword, me.email());
        if (currentPassword != null && currentPassword.equals(newPassword)) {
            throw ApiException.badRequest("The new password must be different from the current one");
        }
        reauth.verifyIdentity(me.userId(), currentPassword, code);
        String hash = passwordEncoder.encode(newPassword);
        User user = tx.execute(status -> {
            Instant now = Instant.now();
            resetTokens.consumeAllForUser(me.userId(), now);
            User managed = users.findByIdForUpdate(me.userId()).orElseThrow();
            managed.setPasswordHash(hash);
            managed.setPasswordChangedAt(now);
            return managed;
        });
        sessions.revokeOthers(me.userId(), me.sessionId());
        mfa.invalidateChallenges(me.userId());
        events.add(SecurityEventType.PASSWORD_CHANGED, user);
        email.sendSecurityNotice(user.getEmail(), "Your password was changed",
                "The password for your account was just changed, and your other devices were signed out.");
    }

    /**
     * Starts an email change: a link goes to the new address, a heads-up to the old one.
     * Replies the same whether or not the new address is taken, so a signed-in user
     * can't use this to discover other accounts.
     */
    public void requestEmailChange(AuthPrincipal me, String rawNewEmail) {
        reauth.require(me);
        String newAddress = EmailAddress.normalize(rawNewEmail);
        if (me.email().equals(newAddress)) {
            throw ApiException.badRequest("That's already your email address");
        }
        String problem = deliverability.problem(newAddress);
        if (problem != null) {
            throw ApiException.badRequest(problem);
        }
        tx.executeWithoutResult(status -> {
            User user = users.findById(me.userId()).orElseThrow();
            events.add(SecurityEventType.EMAIL_CHANGE_REQUESTED, user, "to " + newAddress);
            if (users.existsByEmail(newAddress)) {
                return;
            }
            Instant now = Instant.now();
            emailChangeTokens.consumeAllForUser(me.userId(), now);
            String raw = Tokens.newOpaqueToken();
            EmailChangeToken token = new EmailChangeToken();
            token.setUser(users.getReferenceById(me.userId()));
            token.setNewEmail(newAddress);
            token.setTokenHash(Tokens.sha256(raw));
            token.setExpiresAt(now.plus(Duration.ofHours(props.emailChangeTokenHours())));
            emailChangeTokens.save(token);
            email.sendEmailChangeConfirmation(newAddress, raw);
        });
        email.sendSecurityNotice(me.email(), "Email change requested",
                "Someone signed in to your account asked to change its email address to " + newAddress
                        + ". It changes only if the link sent there is clicked.");
    }

    /** Deletes the account and everything attached to it. Requires a fresh re-authentication. */
    public void deleteAccount(AuthPrincipal me) {
        reauth.require(me);
        tx.executeWithoutResult(status -> {
            User user = users.findByIdForUpdate(me.userId()).orElseThrow();
            if (user.getRole() == Role.ADMIN && users.countByRole(Role.ADMIN) <= 1) {
                throw ApiException.badRequest(
                        "You're the only administrator. Make someone else an administrator first.");
            }
            events.add(SecurityEventType.ACCOUNT_DELETED, user, "by its owner");
            users.delete(user);
        });
        email.sendSecurityNotice(me.email(), "Your account was deleted",
                "Your account and its data were deleted at your request.");
    }

    /**
     * Everything stored about the caller, as JSON (GDPR Art. 15 / 20). Secrets are
     * excluded — password hash, TOTP secret, recovery codes — they're not "data about"
     * anyone and would only add risk to the download.
     */
    public Map<String, Object> export(AuthPrincipal me) {
        User user = users.findById(me.userId()).orElseThrow();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("exportedAt", Instant.now());
        out.put("account", Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "name", user.getName() == null ? "" : user.getName(),
                "role", user.getRole().name(),
                CREATED_AT, user.getCreatedAt(),
                "lastLoginAt", String.valueOf(user.getLastLoginAt()),
                "passwordChangedAt", String.valueOf(user.getPasswordChangedAt()),
                "twoFactorEnabled", user.isTotpEnabled()));
        out.put("sessions", sessions.active(me.userId()).stream().map(s -> Map.of(
                CREATED_AT, s.getCreatedAt(),
                "lastSeenAt", s.getLastSeenAt(),
                "ip", String.valueOf(s.getIp()),
                "userAgent", String.valueOf(s.getUserAgent()),
                "method", s.getAuthMethod().name())).toList());
        out.put("passkeys", passkeys.list(me.userId()).stream().map(p -> Map.of(
                "label", p.getLabel(),
                CREATED_AT, p.getCreatedAt(),
                "lastUsedAt", String.valueOf(p.getLastUsedAt()))).toList());
        List<SecurityEvent> history = eventRepository.findByUserIdOrderByOccurredAtDescIdDesc(me.userId());
        out.put("securityEvents", history.stream().map(e -> Map.of(
                "occurredAt", e.getOccurredAt(),
                "type", e.getType().name(),
                "ip", String.valueOf(e.getIp()),
                "detail", String.valueOf(e.getDetail()))).toList());
        events.add(SecurityEventType.ACCOUNT_EXPORTED, user);
        return out;
    }
}
