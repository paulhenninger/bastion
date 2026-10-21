package dev.bastion.admin;

import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailAddress;
import dev.bastion.user.Role;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates the first administrator without a default password, a seeded account or a
 * password in a log file.
 *
 * <p>Set {@code BOOTSTRAP_ADMIN_EMAIL}. When an account with that address has verified
 * its email — i.e. someone proved they read that inbox — and <em>no administrator exists
 * yet</em>, it is promoted. Checked at startup and at each verification. Once any admin
 * exists this does nothing, so leaving the variable set can't re-promote a demoted
 * account or mint a second admin.
 */
@Service
public class BootstrapAdmin {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdmin.class);

    private final UserRepository users;
    private final SecurityEvents events;
    private final String bootstrapEmail;

    public BootstrapAdmin(UserRepository users, SecurityEvents events, AppProperties props) {
        this.users = users;
        this.events = events;
        this.bootstrapEmail = EmailAddress.normalize(props.admin().bootstrapEmail());
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void onStartup() {
        if (bootstrapEmail == null || bootstrapEmail.isBlank()) {
            return;
        }
        users.findByEmail(bootstrapEmail).ifPresentOrElse(this::promoteIfEligible,
                () -> log.info("Bootstrap admin {} has not signed up yet; it will be promoted once verified",
                        bootstrapEmail));
    }

    /** Called with a managed user, inside the caller's transaction. */
    public void promoteIfEligible(User user) {
        if (bootstrapEmail == null || bootstrapEmail.isBlank()
                || !bootstrapEmail.equals(user.getEmail())
                || !user.isEnabled() || user.getRole() == Role.ADMIN
                || users.countByRole(Role.ADMIN) > 0) {
            return;
        }
        user.setRole(Role.ADMIN);
        users.save(user);
        log.warn("Promoted bootstrap administrator (user {})", user.getId());
        events.add(SecurityEventType.ADMIN_BOOTSTRAPPED, user);
    }
}
