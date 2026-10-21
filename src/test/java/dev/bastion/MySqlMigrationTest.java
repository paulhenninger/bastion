package dev.bastion;

import dev.bastion.auth.AuthController;
import dev.bastion.email.EmailService;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mysql.MySQLContainer;

import java.sql.DriverManager;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The real Flyway migrations on real MySQL — the H2 suite can't run them. Proves that
 * a 1.x database upgrades with its users intact, that the schema matches the entities
 * exactly (Hibernate {@code validate}), and that the row-locking queries work on InnoDB.
 * Skipped when Docker isn't available; CI always has it.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.datasource.url=",
        "spring.datasource.driver-class-name=",
        "app.admin.bootstrap-email="})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MySqlMigrationTest {

    @Container
    @ServiceConnection
    static final MySQLContainer MYSQL = new MySQLContainer("mysql:8.4").withCommand("--character-set-server=utf8mb4");

    static {
        // Before Spring starts (and migrates to latest): build a 1.x database with a live
        // user and a refresh token, exactly as Bastion 1.0 would have left it.
        MYSQL.start();
        Flyway.configure().dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword())
                .target("1").load().migrate();
        try (var c = DriverManager.getConnection(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword());
             var user = c.prepareStatement("insert into users (email, password_hash, enabled, created_at, updated_at) "
                     + "values ('legacy@example.com', ?, true, '2026-08-01 12:00:00', '2026-08-01 12:00:00')");
             var token = c.prepareStatement("insert into refresh_tokens (user_id, token_hash, expires_at) "
                     + "values (1, repeat('a', 64), '2026-12-01 00:00:00')")) {
            user.setString(1, new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder()
                    .encode("legacy-user-password"));
            user.executeUpdate();
            token.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Autowired
    MockMvc mvc;
    @Autowired
    JdbcTemplate jdbc;
    @MockitoBean
    EmailService email;
    @Autowired
    jakarta.persistence.EntityManagerFactory entityManagerFactory;

    @Test
    @Order(1)
    void upgradeKeepsUsersAndDropsPreSessionRefreshTokens() {
        assertThat(jdbc.queryForObject("select count(*) from users", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from refresh_tokens", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select data_type from information_schema.columns "
                + "where table_name = 'users' and column_name = 'created_at'", String.class)).isEqualTo("datetime");
    }

    @Test
    @Order(2)
    void legacyUserSignsInOnMysqlAndIsRehashed() throws Exception {
        MvcResult login = mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                        .content("{\"email\":\"legacy@example.com\",\"password\":\"legacy-user-password\"}"))
                .andExpect(status().isOk()).andReturn();
        assertThat(jdbc.queryForObject("select password_hash from users", String.class)).startsWith("{argon2}");
        // The locked rotation query, on InnoDB.
        mvc.perform(post("/api/v1/auth/refresh").header(AuthController.CLIENT_HEADER, "web")
                        .cookie(login.getResponse().getCookie(AuthController.REFRESH_COOKIE)))
                .andExpect(status().isOk());
    }

    @Test
    @Order(3)
    void signupAndVerifyWorkOnMysql() throws Exception {
        mvc.perform(post("/api/v1/auth/signup").contentType("application/json")
                        .content("{\"email\":\"fresh@example.com\",\"password\":\"a-long-new-passphrase\"}"))
                .andExpect(status().isCreated());
        ArgumentCaptor<String> token = ArgumentCaptor.forClass(String.class);
        verify(email).sendVerificationEmail(eq("fresh@example.com"), token.capture());
        MvcResult verified = mvc.perform(post("/api/v1/auth/verify-email").contentType("application/json")
                        .content(new tools.jackson.databind.json.JsonMapper().writeValueAsString(
                                Map.of("token", token.getValue(), "password", "a-long-new-passphrase"))))
                .andExpect(status().isOk()).andReturn();
        String access = new tools.jackson.databind.json.JsonMapper()
                .readTree(verified.getResponse().getContentAsString()).get("accessToken").asString();
        mvc.perform(get("/api/v1/users/me/sessions").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
    }

    /**
     * Hibernate's {@code validate} checks column types, not lengths, and the H2 suite
     * builds its schema from the entities — so an enum constant longer than its
     * migration's VARCHAR passes everything until it is first written on MySQL. 2.0.0
     * shipped exactly that ({@code PASSWORD_RECOVERY_CODE} in a VARCHAR(20)): recovery
     * codes couldn't sign anyone in. Every enum-valued column, every constant, checked.
     */
    @Test
    @Order(4)
    void everyEnumConstantFitsItsColumn() {
        int checked = 0;
        for (var entity : entityManagerFactory.getMetamodel().getEntities()) {
            Class<?> type = entity.getJavaType();
            String table = type.getAnnotation(jakarta.persistence.Table.class).name();
            for (var field : type.getDeclaredFields()) {
                if (!field.isAnnotationPresent(jakarta.persistence.Enumerated.class)) {
                    continue;
                }
                var column = field.getAnnotation(jakarta.persistence.Column.class);
                String name = column != null && !column.name().isEmpty() ? column.name() : field.getName();
                Integer width = jdbc.queryForObject("select character_maximum_length from information_schema.columns "
                        + "where table_schema = database() and table_name = ? and column_name = ?",
                        Integer.class, table, name);
                for (Object constant : field.getType().getEnumConstants()) {
                    assertThat(((Enum<?>) constant).name().length())
                            .as("%s.%s = %s", table, name, constant)
                            .isLessThanOrEqualTo(width);
                }
                checked++;
            }
        }
        assertThat(checked).isGreaterThanOrEqualTo(4);
    }
}
