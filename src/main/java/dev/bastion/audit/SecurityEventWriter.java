package dev.bastion.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Stores a security event off the request thread.
 *
 * <p>Its own bean because {@code @Async} works through the proxy. Asynchronous for
 * two reasons that both matter: a refused sign-in throws, which rolls back the
 * caller's transaction — an event written inside it would vanish with the very
 * failure it records; and the alternative, a nested REQUIRES_NEW transaction, takes
 * a second pooled connection while the caller holds its first, so enough concurrent
 * sign-ins would each wait on a connection another holds.
 */
@Service
class SecurityEventWriter {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventWriter.class);

    private final SecurityEventRepository repository;

    SecurityEventWriter(SecurityEventRepository repository) {
        this.repository = repository;
    }

    @Async
    public void write(SecurityEvent event) {
        try {
            repository.save(event);
        } catch (RuntimeException e) {
            // The log must never be the reason a sign-in or a password change fails.
            log.warn("Could not store security event {}: {}", event.getType(), e.toString());
        }
    }
}
