package dev.bastion.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

/**
 * Refuses to start a real deployment whose database login can do more than read and
 * write rows.
 *
 * <p>db/roles.sql creates two logins: {@code bastion_owner}, which Flyway uses at
 * startup to migrate, and {@code bastion_app}, which can only select, insert, update
 * and delete. With that split a flaw in the app (SQL injection, say) reaches the rows
 * the app already handles; it cannot drop a table, change the schema, read another
 * database or take over the server. scripts/verify-stack.sh proves this for the
 * Compose stack in CI, but a deployment configured by hand can still point
 * {@code DB_USER} at the owner or at root, and it would run without complaint. So,
 * once {@code APP_BASE_URL} names another host (as for {@link DeploymentSafetyCheck}),
 * the app asks MySQL what its own login may do, and refuses if it holds:
 *
 * <ul>
 *   <li>any global privilege (a right over the whole server);</li>
 *   <li>on this database or a table in it, anything beyond SELECT, INSERT, UPDATE and
 *       DELETE, or the right to grant;</li>
 *   <li>an active role, whose rights this check cannot see (roles.sql sets none).</li>
 * </ul>
 *
 * <p>{@code ALLOW_DEVELOPMENT_SETTINGS=true} skips it, as it skips the other checks.
 */
@Component
public class DatabaseLoginCheck implements InitializingBean {

    /** What MySQL says about the login the app runs as. */
    record Login(String name, boolean serverWide, boolean beyondRows, int activeRoles) {
    }

    /**
     * MySQL names a grantee {@code 'user'@'host'} in information_schema; current_user()
     * returns {@code user@host}, so it is re-quoted to match. A schema-level grant may be
     * a pattern ({@code `app\_%`.*}), hence LIKE rather than equality. USAGE means no
     * privilege at all.
     */
    private static final String INSPECT = """
            select current_user(),
                   exists (select 1 from information_schema.user_privileges p
                           where p.grantee = me.grantee and p.privilege_type <> 'USAGE'),
                   exists (select 1 from information_schema.schema_privileges p
                           where p.grantee = me.grantee and database() like p.table_schema
                             and (p.is_grantable = 'YES'
                                  or p.privilege_type not in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')))
                   or exists (select 1 from information_schema.table_privileges p
                              where p.grantee = me.grantee and database() like p.table_schema
                                and (p.is_grantable = 'YES'
                                     or p.privilege_type not in ('SELECT', 'INSERT', 'UPDATE', 'DELETE'))),
                   (select count(*) from information_schema.enabled_roles)
            from (select concat('''', substring_index(current_user(), '@', 1), '''@''',
                                substring_index(current_user(), '@', -1), '''') as grantee) me
            """;

    private final AppProperties props;
    private final DataSource dataSource;
    private final Environment env;

    public DatabaseLoginCheck(AppProperties props, DataSource dataSource, Environment env) {
        this.props = props;
        this.dataSource = dataSource;
        this.env = env;
    }

    @Override
    public void afterPropertiesSet() {
        if (DeploymentSafetyCheck.isLocal(props.baseUrl())
                || env.getProperty("app.security.allow-development-settings", Boolean.class, false)) {
            return;
        }
        List<String> problems = problems(inspect(new JdbcTemplate(dataSource)));
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Refusing to start " + props.baseUrl() + ":\n  - "
                    + String.join("\n  - ", problems)
                    + "\nRun db/roles.sql as an administrator, then set DB_USER=bastion_app and "
                    + "SPRING_FLYWAY_USER=bastion_owner (with their passwords): migrations run as the owner, "
                    + "everything else as a login that can only read and write rows. "
                    + "See docs/operations.md#production-checklist.");
        }
    }

    static Login inspect(JdbcTemplate jdbc) {
        return jdbc.queryForObject(INSPECT, (rs, row) ->
                new Login(rs.getString(1), rs.getBoolean(2), rs.getBoolean(3), rs.getInt(4)));
    }

    /** What is wrong with this login for everyday use; empty when it can only read and write rows. */
    static List<String> problems(Login login) {
        List<String> problems = new ArrayList<>();
        if (login.serverWide()) {
            problems.add("the app's database login " + login.name() + " holds rights over the whole server");
        }
        if (login.beyondRows()) {
            problems.add("the app's database login " + login.name()
                    + " may change this database's tables or grant rights, not only read and write rows");
        }
        if (login.activeRoles() > 0) {
            problems.add("the app's database login " + login.name()
                    + " has an active role, whose rights cannot be checked (db/roles.sql sets none)");
        }
        return problems;
    }
}
