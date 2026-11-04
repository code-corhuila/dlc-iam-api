package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcDisableStaffUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.DisableStaffAccountService;
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

/** Disposable database must include staff lifecycle and request-audit migrations. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class DisableStaffJdbcIT {
    @Test
    void disableIsOwnerScopedIdempotentAndAtomicWithSessionRevocation() {
        String url = System.getenv("IAM_TEST_JDBC_URL");
        var source = new DriverManagerDataSource(url, "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var owner = new JdbcTemplate(new DriverManagerDataSource(url, "postgres", ""));
        var service = new DisableStaffAccountService(new JdbcDisableStaffUnitOfWork(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source)),
            new ObjectMapper()), Clock.systemUTC());
        UUID admin = UUID.randomUUID();
        UUID staff = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        UUID family = UUID.randomUUID();
        UUID credential = UUID.randomUUID();
        UUID key = UUID.randomUUID();
        UUID correlation = UUID.randomUUID();
        Instant created = Instant.now().minusSeconds(60);
        for (UUID id : new UUID[] {admin, staff}) {
            jdbc.update("""
                INSERT INTO iam.users
                  (user_id,email,password_hash,status,email_verified_at,created_at,updated_at,version)
                VALUES (?,?,'test-hash','ACTIVE',?,?,?,1)
                """, id, id + "@example.test", Timestamp.from(created),
                Timestamp.from(created), Timestamp.from(created));
        }
        jdbc.update("INSERT INTO iam.user_roles (user_id,role,assigned_at) VALUES (?,'ADMINISTRATOR',?)",
            admin, Timestamp.from(created));
        jdbc.update("INSERT INTO iam.user_roles (user_id,role,assigned_at) VALUES (?,'DENTIST',?)",
            staff, Timestamp.from(created));
        jdbc.update("""
            INSERT INTO iam.sessions
              (session_id,user_id,created_at,last_user_activity_at,inactivity_expires_at)
            VALUES (?,?,?,?,?)
            """, session, staff, Timestamp.from(created), Timestamp.from(created),
            Timestamp.from(created.plusSeconds(86400)));
        jdbc.update("INSERT INTO iam.refresh_token_families (family_id,session_id,created_at) VALUES (?,?,?)",
            family, session, Timestamp.from(created));
        jdbc.update("""
            INSERT INTO iam.refresh_credentials
              (credential_id,family_id,token_hash,issued_at,expires_at)
            VALUES (?,?,?,?,?)
            """, credential, family, UUID.randomUUID().toString(), Timestamp.from(created),
            Timestamp.from(created.plusSeconds(86400)));

        assertThrows(SecurityException.class,
            () -> service.disable(staff, staff, 1, "Review", key, correlation));
        assertThrows(SecurityException.class,
            () -> service.disable(admin, admin, 1, "Review", key, correlation));
        owner.execute("REVOKE INSERT ON iam.outbox_events FROM iam_runtime");
        try {
            assertThrows(DataAccessException.class,
                () -> service.disable(admin, staff, 1, "Review", key, correlation));
            assertEquals("ACTIVE", value(jdbc, "SELECT status FROM iam.users WHERE user_id = ?", staff));
            assertEquals(1, count(jdbc, "SELECT version FROM iam.users WHERE user_id = ?", staff));
            assertEquals(0, count(jdbc,
                "SELECT count(*) FROM iam.staff_account_audit WHERE user_id = ?", staff));
            assertEquals(0, count(jdbc,
                "SELECT count(*) FROM iam.sessions WHERE session_id = ? AND revoked_at IS NOT NULL",
                session));
            assertEquals(0, count(jdbc,
                "SELECT count(*) FROM iam.refresh_token_families WHERE family_id = ? AND revoked_at IS NOT NULL",
                family));
            assertEquals(0, count(jdbc,
                "SELECT count(*) FROM iam.refresh_credentials WHERE credential_id = ? AND revoked_at IS NOT NULL",
                credential));
        } finally {
            owner.execute("GRANT INSERT ON iam.outbox_events TO iam_runtime");
        }

        assertEquals(2, service.disable(admin, staff, 1, "Review", key, correlation).version());
        assertEquals("DISABLED", value(jdbc, "SELECT status FROM iam.users WHERE user_id = ?", staff));
        assertEquals(1, count(jdbc, """
            SELECT count(*) FROM iam.staff_account_audit
             WHERE user_id = ? AND actor_user_id = ? AND prior_status = 'ACTIVE'
               AND next_status = 'DISABLED' AND reason = 'Review'
               AND expected_version = 1 AND idempotency_key = ? AND correlation_id = ?
            """, staff, admin, key, correlation));
        assertEquals(1, count(jdbc, """
            SELECT count(*) FROM iam.outbox_events WHERE aggregate_id = ?
              AND event_type = 'SessionRevoked' AND payload ->> 'reason' = 'ACCOUNT_DISABLED'
              AND payload ->> 'userId' = ? AND payload ->> 'sessionId' = ?
              AND NOT jsonb_exists(payload, 'actorId')
            """, session, staff.toString(), session.toString()));
        assertEquals(1, count(jdbc, """
            SELECT count(*) FROM iam.sessions WHERE session_id = ? AND revoked_at IS NOT NULL
              AND revocation_reason = 'ACCOUNT_DISABLED'
            """, session));
        assertEquals(1, count(jdbc,
            "SELECT count(*) FROM iam.refresh_token_families WHERE family_id = ? AND revoked_at IS NOT NULL",
            family));
        assertEquals(1, count(jdbc,
            "SELECT count(*) FROM iam.refresh_credentials WHERE credential_id = ? AND revoked_at IS NOT NULL",
            credential));
        assertEquals(2, service.disable(admin, staff, 1, "Review", key, correlation).version());
        assertEquals(1, count(jdbc,
            "SELECT count(*) FROM iam.outbox_events WHERE aggregate_id = ?", session));
        assertThrows(ConcurrentModificationException.class,
            () -> service.disable(admin, staff, 1, "Different", key, correlation));
        assertThrows(ConcurrentModificationException.class,
            () -> service.disable(admin, staff, 1, "Review", UUID.randomUUID(), correlation));
    }

    private static int count(JdbcTemplate jdbc, String sql, Object... args) {
        return jdbc.queryForObject(sql, Integer.class, args);
    }

    private static String value(JdbcTemplate jdbc, String sql, UUID id) {
        return jdbc.queryForObject(sql, String.class, id);
    }
}
