package dev.bastion.config;

import dev.bastion.config.DatabaseLoginCheck.Login;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A deployment must not run as a database login that can change the schema. The SQL
 * that reads the login's rights runs against real MySQL in MySqlMigrationTest.
 */
class DatabaseLoginCheckTest {

    @Test
    void aLoginThatOnlyReadsAndWritesRowsPasses() {
        assertThat(DatabaseLoginCheck.problems(new Login("bastion_app@%", false, false, 0))).isEmpty();
    }

    @Test
    void theOwnerRootOrARoleIsRefusedWithEveryProblemListed() {
        assertThat(DatabaseLoginCheck.problems(new Login("bastion_owner@%", false, true, 0)))
                .singleElement().asString().contains("bastion_owner@%", "change this database's tables");
        assertThat(DatabaseLoginCheck.problems(new Login("root@%", true, true, 0))).hasSize(2)
                .anySatisfy(p -> assertThat(p).contains("whole server"));
        assertThat(DatabaseLoginCheck.problems(new Login("bastion_app@%", false, false, 1)))
                .singleElement().asString().contains("active role");
    }
}
