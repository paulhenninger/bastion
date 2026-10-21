package dev.bastion.email;

import dev.bastion.config.AppProperties;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Plain-SMTP delivery, fully env-driven. Dev default is the Mailpit catcher in the
 * compose stack (web UI at http://localhost:8025) — nothing leaves the machine. Point
 * MAIL_* at any relay (SES, Postmark, Mailgun SMTP) for production, with STARTTLS on.
 *
 * <p>{@code @Async}: a slow relay must never hold a request hostage. Failures are
 * logged and counted ({@code bastion.mail.failures}), never surfaced to the caller.
 */
@Component
class AsyncMailer {

    private static final Logger log = LoggerFactory.getLogger(AsyncMailer.class);

    private final JavaMailSender mailSender;
    private final AppProperties props;
    private final MeterRegistry meters;

    AsyncMailer(JavaMailSender mailSender, AppProperties props, MeterRegistry meters) {
        this.mailSender = mailSender;
        this.props = props;
        this.meters = meters;
    }

    @Async
    public void send(String to, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(props.mailFrom());
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            mailSender.send(message);
            meters.counter("bastion.mail.sent").increment();
        } catch (Exception e) {
            meters.counter("bastion.mail.failures").increment();
            // The recipient is personal data; the subject identifies the flow well enough.
            log.error("Failed to send '{}' email: {}", subject, e.toString());
        }
    }
}
