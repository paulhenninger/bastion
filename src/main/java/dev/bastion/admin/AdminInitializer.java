package dev.bastion.admin;

import dev.bastion.security.Tokens;
import dev.bastion.user.Role;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Dev/bootstrap convenience: seeds an admin account with a generated password
 * logged at startup. DISABLED under the prod profile — create your first real
 * admin by promoting a signed-up user directly in the database, then use the
 * admin UI for everyone after.
 */
@Configuration
@Profile("!prod")
public class AdminInitializer {

    private static final Logger log = LoggerFactory.getLogger(AdminInitializer.class);
    private static final String ADMIN_EMAIL = "admin@bastion.local";

    @Bean
    ApplicationRunner seedAdmin(UserRepository users, PasswordEncoder passwordEncoder) {
        return args -> {
            if (users.existsByEmail(ADMIN_EMAIL)) {
                return;
            }
            String password = Tokens.newOpaqueToken().substring(0, 16);
            User admin = new User();
            admin.setEmail(ADMIN_EMAIL);
            admin.setPasswordHash(passwordEncoder.encode(password));
            admin.setName("Admin");
            admin.setRole(Role.ADMIN);
            admin.setEnabled(true);
            users.save(admin);
            log.warn("Seeded dev admin account: {} / {}", ADMIN_EMAIL, password);
        };
    }
}
