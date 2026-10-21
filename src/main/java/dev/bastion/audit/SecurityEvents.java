package dev.bastion.audit;

import dev.bastion.config.AppProperties;
import dev.bastion.security.ClientInfo;
import dev.bastion.user.User;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

/**
 * The security log: sign-ins and failed sign-ins, and every change to how an account
 * can be signed in to, each with where it came from. It answers the question nothing
 * else can after the fact — <i>what happened to this account, and from where?</i>
 *
 * <p>Each event goes three places:
 * <ol>
 *   <li>the {@code security_events} table — the admin viewer and each user's own
 *       "recent activity" read it;</li>
 *   <li>one line on the {@code bastion.audit} logger — ship it to a SIEM; with the
 *       {@code prod} profile it is structured JSON;</li>
 *   <li>the {@code bastion.security.events} Prometheus counter, tagged by type —
 *       alert on a spike in {@code SIGN_IN_FAILED} or any {@code REFRESH_TOKEN_REUSE}.</li>
 * </ol>
 *
 * <p>Recording is best effort and never fails the caller.
 */
@Service
public class SecurityEvents {

    private static final Logger audit = LoggerFactory.getLogger("bastion.audit");
    private static final Logger log = LoggerFactory.getLogger(SecurityEvents.class);
    private static final int MAX_DETAIL = 255;
    private static final int MAX_EMAIL = 255;

    private final SecurityEventWriter writer;
    private final SecurityEventRepository repository;
    private final MeterRegistry meters;
    private final Duration retention;

    SecurityEvents(SecurityEventWriter writer, SecurityEventRepository repository,
                   MeterRegistry meters, AppProperties props) {
        this.writer = writer;
        this.repository = repository;
        this.meters = meters;
        this.retention = Duration.ofDays(props.security().auditRetentionDays());
    }

    /** Something that happened to {@code user}'s account, done by its owner. */
    public void add(SecurityEventType type, User user) {
        add(type, user, null, null);
    }

    public void add(SecurityEventType type, User user, String detail) {
        add(type, user, null, detail);
    }

    /** @param actor who did it, when that isn't the account's owner (an administrator) */
    public void add(SecurityEventType type, User user, User actor, String detail) {
        try {
            add(type, user == null ? null : user.getId(), user == null ? null : user.getEmail(),
                    actor == null ? null : actor.getId(), detail);
        } catch (RuntimeException e) {
            // e.g. a detached lazy proxy: the log must never fail the action it describes.
            log.warn("Could not record security event {}: {}", type, e.toString());
        }
    }

    /** For events with no account behind them (a failed sign-in for an unknown address). */
    public void addForEmail(SecurityEventType type, String typedEmail, String detail) {
        add(type, null, typedEmail, null, detail);
    }

    private void add(SecurityEventType type, Long userId, String email, Long actorId, String detail) {
        try {
            // Read here, on the request thread: the writer runs on another one.
            ClientInfo client = ClientInfo.current();
            SecurityEvent event = new SecurityEvent(Instant.now(), type, userId, cut(email, MAX_EMAIL),
                    actorId, client.ip(), client.userAgent(), cut(clean(detail), MAX_DETAIL));
            meters.counter("bastion.security.events", "type", type.name()).increment();
            // Key-values become fields in structured (JSON) logs; the message stays readable as text.
            audit.atInfo()
                    .addKeyValue("event", type.name())
                    .addKeyValue("userId", userId)
                    .addKeyValue("actorId", actorId)
                    .addKeyValue("ip", client.ip())
                    .log("security_event type={} userId={} actorId={} ip={} detail={}",
                            type, userId, actorId, client.ip(), event.getDetail());
            writer.write(event);
        } catch (RuntimeException e) {
            log.warn("Could not record security event {}: {}", type, e.toString());
        }
    }

    public java.util.List<SecurityEvent> recentFor(Long userId) {
        return repository.findTop50ByUserIdOrderByOccurredAtDescIdDesc(userId);
    }

    @Transactional
    public int purgeExpired() {
        return repository.purgeOlderThan(Instant.now().minus(retention));
    }

    private static String clean(String value) {
        return value == null ? null : value.replaceAll("\\p{Cntrl}", " ");
    }

    private static String cut(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
