package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcRecoveryRequestUnitOfWork;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Requires an isolated IAM database migrated to the current develop revision. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class RecoveryRequestJdbcIT {
    private final DriverManagerDataSource source = new DriverManagerDataSource(
        System.getenv("IAM_TEST_JDBC_URL"), "iam_runtime", "");
    private final JdbcTemplate jdbc = new JdbcTemplate(source);
    private final JdbcRecoveryRequestUnitOfWork unit = new JdbcRecoveryRequestUnitOfWork(
        jdbc, new TransactionTemplate(new DataSourceTransactionManager(source)));

    @Test
    void activeVerifiedUserGetsHashOnlyChallengeAndNewRequestReplacesIt() {
        UUID user = UUID.randomUUID();
        String email = user + "@example.test";
        Instant at = Instant.now().minusSeconds(2);
        insertUser(user, email, "ACTIVE", true, at);
        UUID first = UUID.randomUUID();
        UUID next = UUID.randomUUID();

        unit.execute(store -> {
            assertEquals(user, store.verifiedUserForUpdate(email));
            store.createChallenge(first, user, "PASSWORD_RECOVERY", "hash-first",
                at, at.plusSeconds(900));
            return null;
        });
        unit.execute(store -> {
            assertEquals(user, store.verifiedUserForUpdate(email));
            store.createChallenge(next, user, "PASSWORD_RECOVERY", "hash-next",
                at, at.plusSeconds(900));
            return null;
        });

        assertNotNull(jdbc.queryForObject(
            "SELECT consumed_at FROM iam.security_challenges WHERE challenge_id=?",
            Timestamp.class, first));
        assertNull(jdbc.queryForObject(
            "SELECT consumed_at FROM iam.security_challenges WHERE challenge_id=?",
            Timestamp.class, next));
        assertEquals("hash-next", jdbc.queryForObject(
            "SELECT token_hash FROM iam.security_challenges WHERE challenge_id=?",
            String.class, next));
        assertEquals(2, jdbc.queryForObject("""
            SELECT count(*) FROM iam.security_challenges
             WHERE user_id=? AND purpose='PASSWORD_RECOVERY'
            """, Integer.class, user));
    }

    @Test
    void unknownPendingAndDisabledAccountsAreNotEligible() {
        Instant at = Instant.now().minusSeconds(2);
        UUID pending = UUID.randomUUID();
        UUID disabled = UUID.randomUUID();
        insertUser(pending, pending + "@example.test", "PENDING_VERIFICATION", false, at);
        insertUser(disabled, disabled + "@example.test", "DISABLED", true, at);
        unit.execute(store -> {
            assertNull(store.verifiedUserForUpdate("missing@example.test"));
            assertNull(store.verifiedUserForUpdate(pending + "@example.test"));
            assertNull(store.verifiedUserForUpdate(disabled + "@example.test"));
            return null;
        });
    }

    @Test
    void failedReplacementRollsBackInvalidationOfPriorChallenge() {
        UUID user = UUID.randomUUID();
        Instant at = Instant.now().minusSeconds(2);
        insertUser(user, user + "@example.test", "ACTIVE", true, at);
        UUID first = UUID.randomUUID();
        unit.execute(store -> {
            store.createChallenge(first, user, "PASSWORD_RECOVERY", "duplicate-hash",
                at, at.plusSeconds(900));
            return null;
        });
        assertThrows(DataAccessException.class, () -> unit.execute(store -> {
            store.createChallenge(UUID.randomUUID(), user, "PASSWORD_RECOVERY", "duplicate-hash",
                at, at.plusSeconds(900));
            return null;
        }));
        assertNull(jdbc.queryForObject(
            "SELECT consumed_at FROM iam.security_challenges WHERE challenge_id=?",
            Timestamp.class, first));
    }

    private void insertUser(UUID user, String email, String status, boolean verified, Instant at) {
        jdbc.update("""
            INSERT INTO iam.users
              (user_id,email,password_hash,status,email_verified_at,created_at,updated_at)
            VALUES (?,?,?, ?,?,?,?)
            """, user, email, "test-hash", status,
            verified ? Timestamp.from(at) : null, Timestamp.from(at), Timestamp.from(at));
    }
}
