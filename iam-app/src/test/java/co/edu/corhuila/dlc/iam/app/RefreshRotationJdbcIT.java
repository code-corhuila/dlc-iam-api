package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcRefreshRotationUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.RotateRefreshService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Run against a disposable, migrated IAM database as iam_runtime. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class RefreshRotationJdbcIT {
    private static final RefreshCredential TOKENS = new RefreshCredential() {
        public String generate() { return UUID.randomUUID().toString(); }
        public String hash(String raw) { return "hash:" + raw; }
    };

    @Test
    void rotationAndReuseRevokeFamilySessionAndCredentialsOnce() {
        var source = new DriverManagerDataSource(System.getenv("IAM_TEST_JDBC_URL"),
            "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        Instant now = Instant.now();
        Fixture fixture = fixture(jdbc, now);
        var service = service(jdbc, source, new ObjectMapper(), now);

        var result = service.rotate(fixture.rawToken(), UUID.randomUUID());
        assertEquals("signed-access", result.accessToken());
        assertEquals(fixture.userId(), result.user().id());
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.refresh_credentials WHERE "
            + "predecessor_id = ? AND token_hash = ?", fixture.credentialId(),
            TOKENS.hash(result.refreshToken())));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.refresh_credentials WHERE "
            + "credential_id = ? AND consumed_at IS NOT NULL", fixture.credentialId()));
        assertEquals(0, count(jdbc, "SELECT count(*) FROM iam.sessions WHERE session_id = ? "
            + "AND last_user_activity_at > ?", fixture.sessionId(),
            Timestamp.from(now.minusSeconds(60))));

        assertThrows(InvalidLoginException.class,
            () -> service.rotate(fixture.rawToken(), UUID.randomUUID()));
        assertThrows(InvalidLoginException.class,
            () -> service.rotate(fixture.rawToken(), UUID.randomUUID()));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.refresh_token_families "
            + "WHERE family_id = ? AND reuse_detected_at IS NOT NULL", fixture.familyId()));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.sessions WHERE session_id = ? "
            + "AND revoked_at IS NOT NULL", fixture.sessionId()));
        assertEquals(2, count(jdbc, "SELECT count(*) FROM iam.refresh_credentials "
            + "WHERE family_id = ? AND revoked_at IS NOT NULL", fixture.familyId()));
        assertEquals(1, count(jdbc, "SELECT count(*) FROM iam.outbox_events "
            + "WHERE aggregate_id = ? AND event_type = 'SessionRevoked' "
            + "AND payload ->> 'reason' = 'REFRESH_REUSE'", fixture.sessionId()));
    }

    @Test
    void outboxFailureRollsBackReuseRevocation() {
        var source = new DriverManagerDataSource(System.getenv("IAM_TEST_JDBC_URL"),
            "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        Instant now = Instant.now();
        Fixture fixture = fixture(jdbc, now);
        service(jdbc, source, new ObjectMapper(), now)
            .rotate(fixture.rawToken(), UUID.randomUUID());
        var brokenJson = new ObjectMapper() {
            @Override
            public String writeValueAsString(Object value) throws JsonProcessingException {
                throw new JsonProcessingException("forced serialization failure") { };
            }
        };
        assertThrows(IllegalStateException.class,
            () -> service(jdbc, source, brokenJson, now)
                .rotate(fixture.rawToken(), UUID.randomUUID()));
        assertEquals(0, count(jdbc, "SELECT count(*) FROM iam.refresh_token_families "
            + "WHERE family_id = ? AND revoked_at IS NOT NULL", fixture.familyId()));
        assertEquals(0, count(jdbc, "SELECT count(*) FROM iam.sessions WHERE session_id = ? "
            + "AND revoked_at IS NOT NULL", fixture.sessionId()));
    }

    private static RotateRefreshService service(JdbcTemplate jdbc,
                                                DriverManagerDataSource source,
                                                ObjectMapper json, Instant now) {
        var transactions = new TransactionTemplate(new DataSourceTransactionManager(source));
        return new RotateRefreshService(new JdbcRefreshRotationUnitOfWork(jdbc, transactions, json),
            TOKENS, (staff, session, issued, expires) -> "signed-access",
            Clock.fixed(now, ZoneOffset.UTC));
    }

    private static Fixture fixture(JdbcTemplate jdbc, Instant now) {
        UUID user = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        UUID family = UUID.randomUUID();
        UUID credential = UUID.randomUUID();
        String raw = UUID.randomUUID().toString();
        Instant created = now.minusSeconds(60);
        jdbc.update("""
            INSERT INTO iam.users (user_id,email,display_name,password_hash,status,
                                   email_verified_at,created_at,updated_at)
            VALUES (?,?,'Ada','hash','ACTIVE',?,?,?)
            """, user, user + "@example.test", Timestamp.from(created),
            Timestamp.from(created), Timestamp.from(created));
        jdbc.update("INSERT INTO iam.user_roles (user_id,role,assigned_at) "
            + "VALUES (?,'DENTIST',?)", user, Timestamp.from(created));
        jdbc.update("""
            INSERT INTO iam.sessions (session_id,user_id,created_at,last_user_activity_at,
                                      inactivity_expires_at)
            VALUES (?,?,?,?,?)
            """, session, user, Timestamp.from(created), Timestamp.from(created),
            Timestamp.from(now.plusSeconds(86400)));
        jdbc.update("INSERT INTO iam.refresh_token_families "
            + "(family_id,session_id,created_at) VALUES (?,?,?)",
            family, session, Timestamp.from(created));
        jdbc.update("INSERT INTO iam.refresh_credentials "
            + "(credential_id,family_id,token_hash,issued_at,expires_at) "
            + "VALUES (?,?,?,?,?)", credential, family, TOKENS.hash(raw),
            Timestamp.from(created), Timestamp.from(now.plusSeconds(86400)));
        return new Fixture(user, session, family, credential, raw);
    }

    private static int count(JdbcTemplate jdbc, String sql, Object... values) {
        return jdbc.queryForObject(sql, Integer.class, values);
    }

    private record Fixture(UUID userId, UUID sessionId, UUID familyId,
                           UUID credentialId, String rawToken) { }
}
