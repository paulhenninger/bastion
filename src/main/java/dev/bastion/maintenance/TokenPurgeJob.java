package dev.bastion.maintenance;

import dev.bastion.auth.TokenPurgeService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Nightly hygiene: expired and long-revoked token rows are dead weight — and dead
 * secrets. Runs at 03:00 server time; tune with app.maintenance.purge-cron.
 */
@Component
public class TokenPurgeJob {

    private final TokenPurgeService purgeService;

    public TokenPurgeJob(TokenPurgeService purgeService) {
        this.purgeService = purgeService;
    }

    @Scheduled(cron = "${app.maintenance.purge-cron:0 0 3 * * *}")
    public void purge() {
        purgeService.purgeExpired();
    }
}
