package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcOwnSessionRevocationUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.RevokeOwnSessionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Run against a disposable, migrated IAM database as iam_runtime. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class OwnSessionRevocationJdbcIT {
    @Test
    void ownerRevocationCascadesAndReplaysWithoutDuplicateOutbox() {
        var dataSource = new DriverManagerDataSource(System.getenv("IAM_TEST_JDBC_URL"),
            "iam_runtime", "");
        var jdbc = new JdbcTemplate(dataSource);
        var transactions = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        var service = new RevokeOwnSessionService(
            new JdbcOwnSessionRevocationUnitOfWork(jdbc, transactions, new ObjectMapper()),
            Clock.systemUTC());
        UUID owner = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        UUID family = UUID.randomUUID();
        UUID credential = UUID.randomUUID();
        UUID key = UUID.randomUUID();
        Instant created = Instant.now().minusSeconds(60);
        jdbc.update("""
            INSERT INTO iam.users (user_id,email,password_hash,status,email_verified_at,
                                   created_at,updated_at)
            VALUES (?,?,'test-hash','ACTIVE',?,?,?)
            """, owner, owner + "@example.test", Timestamp.from(created),
            Timestamp.from(created), Timestamp.from(created));
        jdbc.update("""
            INSERT INTO iam.sessions (session_id,user_id,created_at,last_user_activity_at,
                                      inactivity_expires_at)
            VALUES (?,?,?,?,?)
            """, session, owner, Timestamp.from(created), Timestamp.from(created),
            Timestamp.from(created.plusSeconds(86400)));
        jdbc.update("INSERT INTO iam.refresh_token_families (family_id,session_id,created_at) VALUES (?,?,?)",
            family, session, Timestamp.from(created));
        jdbc.update("""
            INSERT INTO iam.refresh_credentials
              (credential_id,family_id,token_hash,issued_at,expires_at)
            VALUES (?,?,?,?,?)
            """, credential, family, UUID.randomUUID().toString(), Timestamp.from(created),
            Timestamp.from(created.plusSeconds(86400)));

        if ("1".equals(System.getenv("IAM_TEST_DENY_OUTBOX"))) {
            assertThrows(DataAccessException.class,
                () -> service.revoke(owner, session, key, "User request", UUID.randomUUID()));
            assertEquals(0, count(jdbc, "iam.sessions", "revoked_at IS NOT NULL",
                session, "session_id"));
            assertEquals(0, count(jdbc, "iam.refresh_token_families", "revoked_at IS NOT NULL",
                family, "family_id"));
            assertEquals(0, count(jdbc, "iam.outbox_events", "event_type = 'SessionRevoked'",
                session, "aggregate_id"));
            return;
        }
        service.revoke(owner, session, key, "User request", UUID.randomUUID());
        service.revoke(owner, session, key, "User request", UUID.randomUUID());
        assertEquals(1, count(jdbc, "iam.sessions", "revoked_at IS NOT NULL", session, "session_id"));
        assertEquals(1, count(jdbc, "iam.refresh_token_families", "revoked_at IS NOT NULL",
            family, "family_id"));
        assertEquals(1, count(jdbc, "iam.refresh_credentials", "revoked_at IS NOT NULL",
            credential, "credential_id"));
        assertEquals(1, count(jdbc, "iam.outbox_events", "event_type = 'SessionRevoked'",
            session, "aggregate_id"));
        assertThrows(IllegalStateException.class,
            () -> service.revoke(owner, session, key, "Other reason", UUID.randomUUID()));
        assertThrows(java.util.NoSuchElementException.class,
            () -> service.revoke(UUID.randomUUID(), session, UUID.randomUUID(),
                "User request", UUID.randomUUID()));
    }

    private static int count(JdbcTemplate jdbc, String table, String predicate, UUID id,
                             String keyColumn) {
        // Identifiers above are fixed literals owned by this test, never request data.
        return jdbc.queryForObject("SELECT count(*) FROM " + table + " WHERE " + keyColumn
            + " = ? AND " + predicate, Integer.class, id);
    }
}
