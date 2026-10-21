package dev.bastion.email;

import dev.bastion.config.AppProperties;
import dev.bastion.security.ClientInfo;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Every message the app sends, as plain text. Plain text on purpose: no HTML to
 * inject into, no tracking pixels, nothing a mail client can render deceptively.
 *
 * <p>Links carry their token in the URL <b>fragment</b> ({@code #token=...}). Browsers
 * never send the fragment to a server, so tokens stay out of web-server access logs,
 * proxy logs and {@code Referer} headers; the SPA reads it and POSTs it.
 *
 * <p>This class composes the message on the caller's thread (where the request's IP and
 * device are known, for security notices) and hands it to {@link AsyncMailer}, which
 * sends asynchronously — a slow relay must never hold a request hostage, and a send
 * that fails must not change what the caller sees (the recovery endpoints reply
 * identically either way).
 */
@Service
public class EmailService {

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private final AsyncMailer sender;
    private final EmailRateLimiter limiter;
    private final AppProperties props;

    public EmailService(AsyncMailer sender, EmailRateLimiter limiter, AppProperties props) {
        this.sender = sender;
        this.limiter = limiter;
        this.props = props;
    }

    public void sendVerificationEmail(String to, String token) {
        send(to, "Verify your email address", """
                Welcome to %s!

                Confirm your email address to activate your account:

                %s

                This link expires in %d hours. If you didn't create an account, ignore this
                email — no account will be activated without the link.
                """.formatted(props.name(), link("/verify-email", token), props.verificationTokenHours()));
    }

    /** Someone tried to sign up with an address that already has an account. */
    public void sendExistingAccountNotice(String to) {
        send(to, "Sign-up attempt for your account", """
                Someone tried to create a new %s account with this email address, which
                already has one. Nothing about your account was changed.

                If that was you: you can simply sign in, or reset your password here:
                %s/forgot-password

                If it wasn't you, you can ignore this email.
                """.formatted(props.name(), props.baseUrl()));
    }

    /** @param requestedBy the client that asked, captured on the request thread (this may run async) */
    public void sendPasswordResetEmail(String to, String token, ClientInfo requestedBy) {
        send(to, "Reset your password", """
                Someone requested a password reset for your %s account.

                Set a new password here:

                %s

                This link expires in %d minutes and works once. If this wasn't you, ignore this
                email — your password has not changed.%s
                """.formatted(props.name(), link("/reset-password", token), props.resetTokenMinutes(),
                requestContext(requestedBy)));
    }

    /** Sent to the NEW address: clicking proves the requester controls it. */
    public void sendEmailChangeConfirmation(String newAddress, String token) {
        send(newAddress, "Confirm your new email address", """
                Confirm that this should become the email address of your %s account:

                %s

                This link expires in %d hours. If you didn't ask for this, ignore this email.
                """.formatted(props.name(), link("/confirm-email", token), props.emailChangeTokenHours()));
    }

    /**
     * A change to how the account can be signed in to. Every such change notifies the
     * owner, so an account taken over is at least an account whose owner was told.
     */
    public void sendSecurityNotice(String to, String subject, String what) {
        send(to, subject, """
                %s
                %s
                If this was you, no action is needed. If it wasn't, reset your password now:
                %s/forgot-password
                """.formatted(what, requestContext(ClientInfo.current()), props.baseUrl()));
    }

    public void sendNewSignInAlert(String to, String ip, String userAgent, Instant when) {
        send(to, "New sign-in to your account", """
                Your %s account was just signed in to from a device or network we haven't seen recently.

                  When:   %s
                  From:   %s
                  Device: %s

                If this was you, no action is needed. If it wasn't, change your password and
                sign out other sessions from your account settings:
                %s/account
                """.formatted(props.name(), WHEN.format(when), orUnknown(ip), orUnknown(userAgent),
                props.baseUrl()));
    }

    // ----------------------------------------------------------------- helpers

    private void send(String to, String subject, String body) {
        // The cap is per recipient and silent: a suppressed send must look exactly like a
        // sent one, or the limiter becomes an account-enumeration oracle.
        if (limiter.allowSend(to)) {
            sender.send(to, "[" + props.name() + "] " + subject, body);
        }
    }

    private String link(String path, String token) {
        return props.baseUrl() + path + "#token=" + token;
    }

    /** "When / from / device" lines for a notice. */
    private static String requestContext(ClientInfo client) {
        if (client == null || client.ip() == null) {
            return "";
        }
        return """

                  When:   %s
                  From:   %s
                  Device: %s
                """.formatted(WHEN.format(Instant.now()), client.ip(), orUnknown(client.userAgent()));
    }

    private static String orUnknown(String value) {
        return value == null || value.isBlank() ? "unknown" : value;
    }
}
