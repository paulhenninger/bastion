package dev.bastion;

import dev.bastion.support.IntegrationTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The audit trail must survive the production log format. In 2.0.0 the audit logger
 * added a {@code userId} key-value while the auth filter had {@code userId} in the MDC;
 * the ECS encoder refuses duplicate keys, so every security event raised inside an
 * authenticated request was silently dropped from the JSON logs.
 */
@ExtendWith(OutputCaptureExtension.class)
@TestPropertySource(properties = "logging.structured.format.console=ecs")
class StructuredLoggingTest extends IntegrationTest {

    @Test
    void securityEventsInAuthenticatedRequestsReachTheJsonLog(CapturedOutput output) throws Exception {
        Session session = newAccount("logged@example.com");

        mvc.perform(as(session, post("/api/v1/users/me/sessions/revoke-others"))).andExpect(status().isOk());

        assertThat(output.getOut())
                .doesNotContain("failed to append")
                .containsPattern("\"event\":\"OTHER_SESSIONS_REVOKED\"[^\\n]*\"subjectUserId\":" + session.userId());
    }
}
