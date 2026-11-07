package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcVerificationRequestUnitOfWork;
import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcRecoveryRequestLimiter;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class VerificationRequestJdbcIT {
    private final DriverManagerDataSource source = new DriverManagerDataSource(
        System.getenv("IAM_TEST_JDBC_URL"), "iam_runtime", "");
    private final JdbcTemplate jdbc = new JdbcTemplate(source);
    private final JdbcVerificationRequestUnitOfWork unit = new JdbcVerificationRequestUnitOfWork(
        jdbc, new TransactionTemplate(new DataSourceTransactionManager(source)));

    @Test
    void verificationAndRecoveryHaveIndependentIpWindows() {
        var limiter = new JdbcRecoveryRequestLimiter(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source)),
            Base64.getEncoder().encodeToString(new byte[32]));
        String ip = UUID.randomUUID().toString();
        for (int i = 0; i < 10; i++) {
            org.junit.jupiter.api.Assertions.assertTrue(limiter.allowVerification(ip,
                UUID.randomUUID() + "@example.test"));
        }
        org.junit.jupiter.api.Assertions.assertFalse(limiter.allowVerification(ip,
            UUID.randomUUID() + "@example.test"));
        org.junit.jupiter.api.Assertions.assertTrue(limiter.allow(ip,
            UUID.randomUUID() + "@example.test"));
    }

    @Test
    void onlyPendingAccountGetsReplacementAndOldTokenBecomesUnusable() {
        UUID user = UUID.randomUUID();
        String email = user + "@example.test";
        Instant at = Instant.now().minusSeconds(2);
        insertUser(user, email, "PENDING_VERIFICATION", at);
        UUID first = UUID.randomUUID();
        UUID next = UUID.randomUUID();
        unit.execute(store -> {
            assertEquals(user, store.pendingUserForUpdate(email));
            store.replaceChallenge(first, user, "first-hash", at, at.plusSeconds(86400));
            return null;
        });
        unit.execute(store -> {
            store.replaceChallenge(next, user, "next-hash", at, at.plusSeconds(86400));
            return null;
        });
        assertNotNull(jdbc.queryForObject(
            "SELECT consumed_at FROM iam.security_challenges WHERE challenge_id=?",
            Timestamp.class, first));
        assertNull(jdbc.queryForObject(
            "SELECT consumed_at FROM iam.security_challenges WHERE challenge_id=?",
            Timestamp.class, next));
        assertEquals("EMAIL_VERIFICATION", jdbc.queryForObject(
            "SELECT purpose FROM iam.security_challenges WHERE challenge_id=?",
            String.class, next));
    }

    @Test
    void unknownAndActiveAccountsCannotIssueAndFailedReplacementRollsBack() {
        UUID user = UUID.randomUUID();
        Instant at = Instant.now().minusSeconds(2);
        insertUser(user, user + "@example.test", "PENDING_VERIFICATION", at);
        UUID active = UUID.randomUUID();
        insertUser(active, active + "@example.test", "ACTIVE", at);
        unit.execute(store -> {
            assertNull(store.pendingUserForUpdate("missing@example.test"));
            assertNull(store.pendingUserForUpdate(active + "@example.test"));
            return null;
        });
        UUID first = UUID.randomUUID();
        unit.execute(store -> {
            store.replaceChallenge(first, user, "duplicate-hash", at, at.plusSeconds(86400));
            return null;
        });
        assertThrows(DataAccessException.class, () -> unit.execute(store -> {
            store.replaceChallenge(UUID.randomUUID(), user, "duplicate-hash",
                at, at.plusSeconds(86400));
            return null;
        }));
        assertNull(jdbc.queryForObject(
            "SELECT consumed_at FROM iam.security_challenges WHERE challenge_id=?",
            Timestamp.class, first));
    }

    private void insertUser(UUID user, String email, String status, Instant at) {
        jdbc.update("""
            INSERT INTO iam.users
              (user_id,email,password_hash,status,email_verified_at,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?)
            """, user, email, "test-hash", status,
            "ACTIVE".equals(status) ? Timestamp.from(at) : null,
            Timestamp.from(at), Timestamp.from(at));
    }
}
