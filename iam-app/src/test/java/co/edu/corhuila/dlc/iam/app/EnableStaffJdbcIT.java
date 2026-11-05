package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcEnableStaffUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.EnableStaffAccountService;
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

/** Disposable IAM database must include lifecycle audit request migration 013. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class EnableStaffJdbcIT {
    @Test
    void enablesOnlyOwnedStaffWithAtomicAuditAndIdempotency() {
        String url = System.getenv("IAM_TEST_JDBC_URL");
        var source = new DriverManagerDataSource(url, "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var owner = new JdbcTemplate(new DriverManagerDataSource(url, "postgres", ""));
        var service = new EnableStaffAccountService(new JdbcEnableStaffUnitOfWork(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source))), Clock.systemUTC());
        UUID admin = UUID.randomUUID(), verified = UUID.randomUUID(), unverified = UUID.randomUUID();
        UUID key = UUID.randomUUID(), correlation = UUID.randomUUID();
        Instant at = Instant.now().minusSeconds(60);
        for (UUID id : new UUID[] {admin, verified, unverified}) {
            jdbc.update("""
                INSERT INTO iam.users
                  (user_id,email,password_hash,status,email_verified_at,created_at,updated_at,version)
                VALUES (?,?,'test-hash',?,?,?,?,1)
                """, id, id + "@example.test", id.equals(admin) ? "ACTIVE" : "DISABLED",
                id.equals(unverified) ? null : Timestamp.from(at),
                Timestamp.from(at), Timestamp.from(at));
        }
        jdbc.update("INSERT INTO iam.user_roles (user_id,role,assigned_at) VALUES (?,'ADMINISTRATOR',?)",
            admin, Timestamp.from(at));
        for (UUID id : new UUID[] {verified, unverified}) {
            jdbc.update("INSERT INTO iam.user_roles (user_id,role,assigned_at) VALUES (?,'DENTIST',?)",
                id, Timestamp.from(at));
        }
        assertThrows(SecurityException.class,
            () -> service.enable(verified, unverified, 1, "Reviewed", key, correlation));
        assertThrows(SecurityException.class,
            () -> service.enable(admin, admin, 1, "Reviewed", key, correlation));

        owner.execute("REVOKE INSERT ON iam.staff_account_audit FROM iam_runtime");
        try {
            assertThrows(DataAccessException.class,
                () -> service.enable(admin, verified, 1, "Reviewed", key, correlation));
            assertEquals("DISABLED", status(jdbc, verified));
            assertEquals(1, count(jdbc, "SELECT version FROM iam.users WHERE user_id = ?", verified));
        } finally {
            owner.execute("GRANT INSERT ON iam.staff_account_audit TO iam_runtime");
        }

        assertEquals("ACTIVE", service.enable(admin, verified, 1, "Reviewed", key, correlation).status());
        assertEquals("ACTIVE", status(jdbc, verified));
        assertEquals(2, service.enable(admin, verified, 1, "Reviewed", key, correlation).version());
        assertEquals(1, count(jdbc, """
            SELECT count(*) FROM iam.staff_account_audit WHERE user_id = ? AND action = 'ENABLED'
              AND prior_status = 'DISABLED' AND next_status = 'ACTIVE' AND reason = 'Reviewed'
              AND actor_user_id = ? AND expected_version = 1 AND idempotency_key = ?
              AND correlation_id = ?
            """, verified, admin, key, correlation));
        assertThrows(ConcurrentModificationException.class,
            () -> service.enable(admin, verified, 1, "Different", key, correlation));
        assertThrows(ConcurrentModificationException.class,
            () -> service.enable(admin, verified, 1, "Reviewed", UUID.randomUUID(), correlation));

        UUID otherKey = UUID.randomUUID();
        assertEquals("PENDING_VERIFICATION", service.enable(admin, unverified, 1, "Reviewed",
            otherKey, correlation).status());
        assertEquals("PENDING_VERIFICATION", status(jdbc, unverified));
        assertEquals(0, count(jdbc,
            "SELECT count(*) FROM iam.sessions WHERE user_id = ? AND revoked_at IS NULL", unverified));
    }

    private static int count(JdbcTemplate jdbc, String sql, Object... args) {
        return jdbc.queryForObject(sql, Integer.class, args);
    }

    private static String status(JdbcTemplate jdbc, UUID id) {
        return jdbc.queryForObject("SELECT status FROM iam.users WHERE user_id = ?", String.class, id);
    }
}
