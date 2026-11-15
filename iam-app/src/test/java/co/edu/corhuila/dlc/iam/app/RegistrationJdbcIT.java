package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcRegistrationUnitOfWork;
import co.edu.corhuila.dlc.iam.adapter.out.security.BcryptPasswordHasher;
import co.edu.corhuila.dlc.iam.adapter.out.security.HmacRegistrationRequestProof;
import co.edu.corhuila.dlc.iam.adapter.out.security.Sha256ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.usecase.RegisterStaffService;
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

/** Requires the IAM DB registration-request migration in a disposable PostgreSQL instance. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class RegistrationJdbcIT {
    @Test
    void registersAtomicallyAndReplaysOriginalSnapshotAfterAccountChanges() {
        String url = System.getenv("IAM_TEST_JDBC_URL");
        var source = new DriverManagerDataSource(url, "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var owner = new JdbcTemplate(new DriverManagerDataSource(url, "postgres", ""));
        var service = new RegisterStaffService(new JdbcRegistrationUnitOfWork(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source)), new ObjectMapper()),
            new BcryptPasswordHasher(), new HmacRegistrationRequestProof(new byte[32]),
            Clock.systemUTC(), () -> "initial-verification-token",
            new Sha256ChallengeTokenHasher(), (email, token, correlationId) -> {});
        UUID admin = UUID.randomUUID();
        Instant at = Instant.now().minusSeconds(60);
        jdbc.update("""
            INSERT INTO iam.users
              (user_id,email,password_hash,display_name,status,email_verified_at,
               created_at,updated_at,version)
            VALUES (? ,?,'test-hash','Admin','ACTIVE',?,?,?,1)
            """, admin, admin + "@example.test", Timestamp.from(at), Timestamp.from(at),
            Timestamp.from(at));
        jdbc.update("INSERT INTO iam.user_roles (user_id,role,assigned_at) VALUES (?,'ADMINISTRATOR',?)",
            admin, Timestamp.from(at));

        UUID key = UUID.randomUUID();
        String email = "ada+" + UUID.randomUUID() + "@example.test";
        var first = service.register(admin, "  " + email.toUpperCase() + "  ", "Password1", "Ada Staff",
            "DENTIST", key, UUID.randomUUID());
        assertEquals(email, first.email());
        assertEquals("PENDING_VERIFICATION", first.status());
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.users WHERE user_id=?", first.id()));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.user_roles WHERE user_id=?", first.id()));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.staff_account_audit WHERE user_id=?", first.id()));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.outbox_events WHERE aggregate_id=?", first.id()));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.security_challenges WHERE user_id=?", first.id()));
        byte[] proof = jdbc.queryForObject(
            "SELECT request_proof FROM iam.registration_requests WHERE idempotency_key=?",
            byte[].class, key);
        assertEquals(32, proof.length);
        assertFalse(new String(proof).contains("Password1"));
        owner.update("UPDATE iam.users SET display_name='Changed', version=2 WHERE user_id=?", first.id());
        var replay = service.register(admin, email, "Password1", "Ada Staff",
            "DENTIST", key, UUID.randomUUID());
        assertEquals(first, replay);
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.outbox_events WHERE aggregate_id=?", first.id()));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.security_challenges WHERE user_id=?", first.id()));
        assertThrows(ConcurrentModificationException.class, () -> service.register(admin,
            email, "Password2", "Ada Staff", "DENTIST", key, UUID.randomUUID()));

        UUID rolledBack = UUID.randomUUID();
        owner.execute("REVOKE INSERT ON iam.outbox_events FROM iam_runtime");
        try {
            assertThrows(DataAccessException.class, () -> service.register(admin,
                rolledBack + "@example.test", "Password1", "Other Staff", "DENTIST",
                UUID.randomUUID(), UUID.randomUUID()));
        } finally {
            owner.execute("GRANT INSERT ON iam.outbox_events TO iam_runtime");
        }
        assertEquals(0, count(jdbc, "SELECT count(*) FROM iam.users WHERE email=?",
            rolledBack + "@example.test"));
    }

    private static long count(JdbcTemplate jdbc, String sql, Object value) {
        return jdbc.queryForObject(sql, Long.class, value);
    }
}
