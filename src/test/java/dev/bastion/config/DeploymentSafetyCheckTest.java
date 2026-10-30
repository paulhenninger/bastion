package dev.bastion.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** A deployment must not start on the settings the repository publishes for development. */
class DeploymentSafetyCheckTest {

    private static final String KEY_A = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private static final String KEY_B = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";
    private static final String STRONG = "pL7v-Qk2-strong-db-password-9x";

    @Test
    void localDevelopmentIsNeverRefused() {
        assertThat(DeploymentSafetyCheck.problems("http://localhost:5173", KEY_A, KEY_A, "bastion", null)).isEmpty();
        assertThat(DeploymentSafetyCheck.problems("http://127.0.0.1:8081", KEY_A, KEY_A, "", "")).isEmpty();
    }

    @Test
    void aProperDeploymentStarts() {
        assertThat(DeploymentSafetyCheck.problems("https://app.example.com", KEY_A, KEY_B, STRONG, STRONG + "-owner"))
                .isEmpty();
    }

    @Test
    void aDeploymentOnDevelopmentSettingsIsRefusedWithEveryProblemListed() {
        assertThat(DeploymentSafetyCheck.problems("http://app.example.com", KEY_A, KEY_A, "bastion", "bastion-owner-local"))
                .hasSize(4)
                .anySatisfy(p -> assertThat(p).contains("https://"))
                .anySatisfy(p -> assertThat(p).contains("DB_PASS"))
                .anySatisfy(p -> assertThat(p).contains("SPRING_FLYWAY_PASSWORD"))
                .anySatisfy(p -> assertThat(p).contains("different keys"));
    }

    @Test
    void anEmptyOrMissingDatabasePasswordIsRefused() {
        assertThat(DeploymentSafetyCheck.problems("https://app.example.com", KEY_A, KEY_B, "", null)).hasSize(1);
        assertThat(DeploymentSafetyCheck.problems("https://app.example.com", KEY_A, KEY_B, null, null)).hasSize(1);
    }
}
