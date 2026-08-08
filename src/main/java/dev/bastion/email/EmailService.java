package dev.bastion.email;

import dev.bastion.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Plain-SMTP email, fully env-driven. Dev default is the Mailpit catcher in the
 * compose stack (web UI at http://localhost:8025) — nothing leaves the machine.
 * Point MAIL_* at any relay (SES, Postmark, Mailgun SMTP) for production.
 *
 * <p>Sends are {@code @Async}: a slow relay must never hold a signup request hostage.
 */
@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;
    private final AppProperties props;

    public EmailService(JavaMailSender mailSender, AppProperties props) {
        this.mailSender = mailSender;
        this.props = props;
    }

    @Async
    public void sendVerificationEmail(String to, String token) {
        String link = props.baseUrl() + "/verify-email?token=" + token;
        send(to, "Verify your email",
                """
                Welcome!

                Confirm your email address to activate your account:

                %s

                This link expires in %d hours. If you didn't create an account, ignore this email.
                """.formatted(link, props.verificationTokenHours()));
    }

    @Async
    public void sendPasswordResetEmail(String to, String token) {
        String link = props.baseUrl() + "/reset-password?token=" + token;
        send(to, "Reset your password",
                """
                Someone requested a password reset for this account.

                Set a new password here:

                %s

                This link expires in %d minutes and can be used once. If this wasn't you,
                you can safely ignore this email — your password has not changed.
                """.formatted(link, props.resetTokenMinutes()));
    }

    @Async
    public void sendPasswordChangedNotice(String to) {
        send(to, "Your password was changed",
                """
                Your account password was just changed and all other sessions were signed out.

                If this was you, no action is needed. If it wasn't, reset your password
                immediately using the "Forgot password" link.
                """);
    }

    private void send(String to, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(props.mailFrom());
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            mailSender.send(message);
        } catch (Exception e) {
            // Deliberately swallowed: mail failures are logged, never surfaced to the
            // caller — the enumeration-safe endpoints reply identically either way.
            log.error("Failed to send '{}' email", subject, e);
        }
    }
}
