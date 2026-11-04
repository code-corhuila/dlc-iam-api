package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcUnlockAccountUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.UnlockAccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Run against a disposable IAM database with audit-reasons changeset 012. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class UnlockAccountJdbcIT {
    @Test
    void unlocksAtomicallyAndReplaysOnlyTheSameRequest() {
        String url = System.getenv("IAM_TEST_JDBC_URL");
        var source = new DriverManagerDataSource(url, "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var adminJdbc = new JdbcTemplate(new DriverManagerDataSource(url, "postgres", ""));
        var service = new UnlockAccountService(new JdbcUnlockAccountUnitOfWork(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source)),
            new ObjectMapper()), Clock.systemUTC());
        UUID admin = UUID.randomUUID();
        UUID staff = UUID.randomUUID();
        UUID outsider = UUID.randomUUID();
        UUID key = UUID.randomUUID();
        UUID correlation = UUID.randomUUID();
        Instant created = Instant.now().minusSeconds(60);
        for (UUID id : new UUID[] {admin, staff, outsider}) {
            jdbc.update("""
                INSERT INTO iam.users
                  (user_id,email,password_hash,status,email_verified_at,created_at,updated_at,version)
                VALUES (?,?,'test-hash','ACTIVE',?,?,?,4)
                """, id, id + "@example.test", Timestamp.from(created),
                Timestamp.from(created), Timestamp.from(created));
        }
        jdbc.update("""
            INSERT INTO iam.user_roles (user_id,role,assigned_at)
            VALUES (?,'ADMINISTRATOR',?)
            """, admin, Timestamp.from(created));
        jdbc.update("""
            UPDATE iam.users SET status = 'LOCKED', failed_attempts = 3,
                locked_until = ? WHERE user_id = ?
            """, Timestamp.from(created.plusSeconds(900)), staff);
        assertThrows(SecurityException.class,
            () -> service.unlock(outsider, staff, 4, "Reviewed", key, correlation));

        adminJdbc.execute("REVOKE INSERT ON iam.outbox_events FROM iam_runtime");
        try {
            assertThrows(DataAccessException.class,
                () -> service.unlock(admin, staff, 4, "Reviewed", key, correlation));
            assertEquals("LOCKED", jdbc.queryForObject(
                "SELECT status FROM iam.users WHERE user_id = ?", String.class, staff));
            assertEquals(0, count(jdbc, "iam.account_lock_audit", staff, "user_id"));
        } finally {
            adminJdbc.execute("GRANT INSERT ON iam.outbox_events TO iam_runtime");
        }

        var result = service.unlock(admin, staff, 4, "Reviewed", key, correlation);
        assertEquals("ACTIVE", result.status());
        assertEquals(5, result.version());
        assertEquals(0, jdbc.queryForObject(
            "SELECT failed_attempts FROM iam.users WHERE user_id = ?", Integer.class, staff));
        assertEquals(1, jdbc.queryForObject("""
            SELECT count(*) FROM iam.account_lock_audit
             WHERE user_id = ? AND actor_user_id = ? AND reason = 'Reviewed'
               AND expected_version = 4 AND idempotency_key = ? AND correlation_id = ?
            """, Integer.class, staff, admin, key, correlation));
        assertEquals(1, jdbc.queryForObject("""
            SELECT count(*) FROM iam.outbox_events
             WHERE aggregate_id = ? AND event_type = 'UserUnlocked'
               AND causation_id = ? AND payload ->> 'mode' = 'ADMINISTRATOR'
               AND payload ->> 'performedBy' = ? AND NOT jsonb_exists(payload, 'reason')
            """, Integer.class, staff, key, admin.toString()));
        assertEquals(5, service.unlock(admin, staff, 4, "Reviewed", key,
            UUID.randomUUID()).version());
        assertEquals(1, count(jdbc, "iam.account_lock_audit", staff, "user_id"));
        assertEquals(1, count(jdbc, "iam.outbox_events", staff, "aggregate_id"));
        assertThrows(ConcurrentModificationException.class,
            () -> service.unlock(admin, staff, 4, "Different", key, UUID.randomUUID()));
        assertThrows(ConcurrentModificationException.class,
            () -> service.unlock(admin, staff, 4, "Reviewed", UUID.randomUUID(),
                UUID.randomUUID()));
    }

    private static int count(JdbcTemplate jdbc, String table, UUID id, String column) {
        // Identifiers are fixed literals owned by this test, never request data.
        return jdbc.queryForObject("SELECT count(*) FROM " + table + " WHERE " + column + " = ?",
            Integer.class, id);
    }
}
