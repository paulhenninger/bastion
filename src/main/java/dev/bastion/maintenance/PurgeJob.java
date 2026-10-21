package dev.bastion.maintenance;

import dev.bastion.audit.SecurityEvents;
import dev.bastion.auth.TokenPurge;
import dev.bastion.config.AppProperties;
import dev.bastion.passkey.PasskeyService;
import dev.bastion.session.SessionService;
import dev.bastion.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;

/**
 * Nightly hygiene: expired and long-revoked rows are dead weight — and, for tokens,
 * dead secrets; old security events hold personal data past their usefulness; and
 * unverified accounts squat on addresses. Runs at 03:00 server time
 * ({@code app.maintenance.purge-cron}). Anonymous passkey challenges are swept hourly.
 */
@Component
public class PurgeJob {

    private static final Logger log = LoggerFactory.getLogger(PurgeJob.class);

    private final SessionService sessions;
    private final TokenPurge tokens;
    private final PasskeyService passkeys;
    private final SecurityEvents events;
    private final UserRepository users;
    private final Duration unverifiedTtl;
    private final TransactionTemplate tx;

    public PurgeJob(SessionService sessions, TokenPurge tokens, PasskeyService passkeys, SecurityEvents events,
                    UserRepository users, AppProperties props, PlatformTransactionManager transactionManager) {
        this.sessions = sessions;
        this.tokens = tokens;
        this.passkeys = passkeys;
        this.events = events;
        this.users = users;
        this.unverifiedTtl = Duration.ofDays(props.signup().purgeUnverifiedDays());
        this.tx = new TransactionTemplate(transactionManager);
    }

    @Scheduled(cron = "${app.maintenance.purge-cron:0 0 3 * * *}")
    public void nightly() {
        int sessionRows = sessions.purgeOld();
        int tokenRows = tokens.purgeExpired();
        int eventRows = events.purgeExpired();
        Integer unverified = tx.execute(s -> users.purgeUnverified(Instant.now().minus(unverifiedTtl)));
        log.info("Purge: {} session/refresh rows, {} one-time tokens, {} security events, {} unverified accounts",
                sessionRows, tokenRows, eventRows, unverified);
    }

    @Scheduled(cron = "0 15 * * * *")
    public void hourly() {
        passkeys.purgeExpiredChallenges();
    }
}
