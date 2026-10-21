package dev.bastion.admin;

import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.config.AppProperties;
import dev.bastion.user.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Switches an administrator can flip at runtime without a redeploy. Today one: whether
 * new accounts may be created (close it during an abuse wave, or for an invite-only
 * launch). Enforced on the server, not just hidden in the UI.
 */
@Service
public class SettingsService {

    static final String SIGNUPS_OPEN = "signups.open";

    private final AppSettingRepository repository;
    private final SecurityEvents events;
    private final boolean signupsOpenByDefault;

    public SettingsService(AppSettingRepository repository, SecurityEvents events, AppProperties props) {
        this.repository = repository;
        this.events = events;
        this.signupsOpenByDefault = props.signup().openByDefault();
    }

    @Transactional(readOnly = true)
    public boolean signupsOpen() {
        return repository.findById(SIGNUPS_OPEN)
                .map(s -> Boolean.parseBoolean(s.value))
                .orElse(signupsOpenByDefault);
    }

    @Transactional
    public void setSignupsOpen(boolean open, User admin) {
        AppSetting setting = repository.findById(SIGNUPS_OPEN).orElseGet(() -> new AppSetting(SIGNUPS_OPEN));
        setting.value = String.valueOf(open);
        setting.updatedAt = Instant.now();
        repository.save(setting);
        events.record(open ? SecurityEventType.SIGNUPS_OPENED : SecurityEventType.SIGNUPS_CLOSED, null, admin, null);
    }
}
