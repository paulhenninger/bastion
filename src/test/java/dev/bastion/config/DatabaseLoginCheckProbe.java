package dev.bastion.config;

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

/** Lets tests outside this package run DatabaseLoginCheck's query against a database. */
public final class DatabaseLoginCheckProbe {

    private DatabaseLoginCheckProbe() {
    }

    public static List<String> problems(JdbcTemplate jdbc) {
        return DatabaseLoginCheck.problems(DatabaseLoginCheck.inspect(jdbc));
    }
}
