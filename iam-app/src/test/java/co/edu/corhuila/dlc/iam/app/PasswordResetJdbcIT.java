package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcPasswordResetUnitOfWork;
import co.edu.corhuila.dlc.iam.adapter.out.security.BcryptPasswordHasher;
import co.edu.corhuila.dlc.iam.adapter.out.security.BcryptPasswordVerifier;
import co.edu.corhuila.dlc.iam.adapter.out.security.Sha256ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidRecoveryChallengeException;
import co.edu.corhuila.dlc.iam.application.usecase.ResetPasswordService;
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
class PasswordResetJdbcIT {
    private final DriverManagerDataSource source = new DriverManagerDataSource(
        System.getenv("IAM_TEST_JDBC_URL"), "iam_runtime", "");
    private final JdbcTemplate jdbc = new JdbcTemplate(source);
    private final Sha256ChallengeTokenHasher tokens = new Sha256ChallengeTokenHasher();
    private final ResetPasswordService service = new ResetPasswordService(
        new JdbcPasswordResetUnitOfWork(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source)), new ObjectMapper()),
        tokens, new BcryptPasswordHasher(), Clock.systemUTC());

    @Test
    void consumesOnlyRecoveryChallengeAndDurablyRevokesSessions() {
        UUID user = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        UUID family = UUID.randomUUID();
        UUID credential = UUID.randomUUID();
        UUID challenge = UUID.randomUUID();
        String rawToken = UUID.randomUUID().toString();
        UUID correlation = UUID.randomUUID();
        Instant created = Instant.now().minusSeconds(60);
        insertUser(user, created);
        jdbc.update("""
            INSERT INTO iam.sessions
              (session_id,user_id,created_at,last_user_activity_at,inactivity_expires_at)
            VALUES (?,?,?,?,?)
            """, session, user, Timestamp.from(created), Timestamp.from(created),
            Timestamp.from(created.plusSeconds(86400)));
        jdbc.update("""
            INSERT INTO iam.refresh_token_families (family_id,session_id,created_at)
            VALUES (?,?,?)
            """, family, session, Timestamp.from(created));
        jdbc.update("""
            INSERT INTO iam.refresh_credentials
              (credential_id,family_id,token_hash,issued_at,expires_at)
            VALUES (?,?,?,?,?)
            """, credential, family, tokens.hash(UUID.randomUUID().toString()),
            Timestamp.from(created), Timestamp.from(created.plusSeconds(86400)));
        insertChallenge(challenge, user, "PASSWORD_RECOVERY", rawToken, created,
            created.plusSeconds(3600));

        service.reset(rawToken, "NewPassword9", correlation);

        String hash = jdbc.queryForObject("SELECT password_hash FROM iam.users WHERE user_id=?",
            String.class, user);
        assertTrue(new BcryptPasswordVerifier().matches("NewPassword9", hash));
        assertEquals("ACTIVE", jdbc.queryForObject("SELECT status FROM iam.users WHERE user_id=?",
            String.class, user));
        assertEquals(1L, jdbc.queryForObject("SELECT version FROM iam.users WHERE user_id=?",
            Long.class, user));
        assertNotNull(jdbc.queryForObject("""
            SELECT consumed_at FROM iam.security_challenges WHERE challenge_id=?
            """, Timestamp.class, challenge));
        assertNotNull(jdbc.queryForObject("SELECT revoked_at FROM iam.sessions WHERE session_id=?",
            Timestamp.class, session));
        assertNotNull(jdbc.queryForObject("""
            SELECT revoked_at FROM iam.refresh_token_families WHERE family_id=?
            """, Timestamp.class, family));
        assertNotNull(jdbc.queryForObject("""
            SELECT revoked_at FROM iam.refresh_credentials WHERE credential_id=?
            """, Timestamp.class, credential));
        assertEquals(1, jdbc.queryForObject("""
            SELECT count(*) FROM iam.outbox_events
             WHERE event_type='SessionRevoked' AND aggregate_id=? AND correlation_id=?
            """, Integer.class, session, correlation));
        assertThrows(InvalidRecoveryChallengeException.class,
            () -> service.reset(rawToken, "AnotherPassword9", UUID.randomUUID()));
        assertEquals(1, jdbc.queryForObject("""
            SELECT count(*) FROM iam.outbox_events
             WHERE event_type='SessionRevoked' AND aggregate_id=?
            """, Integer.class, session));
    }

    @Test
    void wrongPurposeExpiredAndUnknownTokensCannotChangePassword() {
        UUID user = UUID.randomUUID();
        Instant created = Instant.now().minusSeconds(3600);
        String verificationToken = UUID.randomUUID().toString();
        String expiredToken = UUID.randomUUID().toString();
        insertUser(user, created);
        insertChallenge(UUID.randomUUID(), user, "EMAIL_VERIFICATION", verificationToken, created,
            Instant.now().plusSeconds(600));
        insertChallenge(UUID.randomUUID(), user, "PASSWORD_RECOVERY", expiredToken, created,
            created.plusSeconds(1800));
        for (String invalid : new String[] {verificationToken, expiredToken,
            UUID.randomUUID().toString()}) {
            assertThrows(InvalidRecoveryChallengeException.class,
                () -> service.reset(invalid, "NewPassword9", UUID.randomUUID()));
        }
        assertEquals("old-hash", jdbc.queryForObject(
            "SELECT password_hash FROM iam.users WHERE user_id=?", String.class, user));
        assertEquals(0, jdbc.queryForObject("""
            SELECT count(*) FROM iam.security_challenges
             WHERE user_id=? AND consumed_at IS NOT NULL
            """, Integer.class, user));
    }

    @Test
    void revocationConstraintFailureRollsBackChallengeAndPassword() {
        UUID user = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        UUID challenge = UUID.randomUUID();
        String rawToken = UUID.randomUUID().toString();
        Instant created = Instant.now().minusSeconds(60);
        Instant futureSession = Instant.now().plusSeconds(3600);
        insertUser(user, created);
        jdbc.update("""
            INSERT INTO iam.sessions
              (session_id,user_id,created_at,last_user_activity_at,inactivity_expires_at)
            VALUES (?,?,?,?,?)
            """, session, user, Timestamp.from(futureSession), Timestamp.from(futureSession),
            Timestamp.from(futureSession.plusSeconds(86400)));
        insertChallenge(challenge, user, "PASSWORD_RECOVERY", rawToken, created,
            created.plusSeconds(7200));

        // The synthetic future session makes revocation fail after challenge consumption
        // and password update. The transaction must keep all three original values.
        assertThrows(DataAccessException.class,
            () -> service.reset(rawToken, "NewPassword9", UUID.randomUUID()));
        assertEquals("old-hash", jdbc.queryForObject(
            "SELECT password_hash FROM iam.users WHERE user_id=?", String.class, user));
        assertNull(jdbc.queryForObject("""
            SELECT consumed_at FROM iam.security_challenges WHERE challenge_id=?
            """, Timestamp.class, challenge));
        assertNull(jdbc.queryForObject("SELECT revoked_at FROM iam.sessions WHERE session_id=?",
            Timestamp.class, session));
        assertEquals(0, jdbc.queryForObject("""
            SELECT count(*) FROM iam.outbox_events WHERE aggregate_id=?
            """, Integer.class, session));
    }

    private void insertUser(UUID user, Instant created) {
        jdbc.update("""
            INSERT INTO iam.users
              (user_id,email,password_hash,status,email_verified_at,created_at,updated_at)
            VALUES (?,?,'old-hash','ACTIVE',?,?,?)
            """, user, user + "@example.test", Timestamp.from(created),
            Timestamp.from(created), Timestamp.from(created));
    }

    private void insertChallenge(UUID challenge, UUID user, String purpose, String raw,
                                 Instant created, Instant expires) {
        jdbc.update("""
            INSERT INTO iam.security_challenges
              (challenge_id,user_id,purpose,token_hash,created_at,expires_at)
            VALUES (?,?,?,?,?,?)
            """, challenge, user, purpose, tokens.hash(raw), Timestamp.from(created),
            Timestamp.from(expires));
    }
}
