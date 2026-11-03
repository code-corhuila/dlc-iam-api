package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcLogoutUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.LogoutService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Run against a disposable, migrated IAM database as iam_runtime. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class LogoutJdbcIT {
    private static final RefreshCredential TOKENS = new RefreshCredential() {
        public String generate() { return UUID.randomUUID().toString(); }
        public String hash(String raw) { return "hash:" + raw; }
    };

    @Test
    void currentSessionOnlyThenAllDevicesRevokesOwnerSessionsAndOutbox() {
        var source = source();
        var jdbc = new JdbcTemplate(source);
        Fixture first = fixture(jdbc);
        Fixture second = fixture(jdbc, first.userId());
        Fixture stranger = fixture(jdbc);
        var service = service(jdbc, source, new ObjectMapper());

        service.logout(first.raw(), false, UUID.randomUUID());
        assertEquals(1, count(jdbc, "iam.sessions", "revoked_at IS NOT NULL", first.sessionId()));
        assertEquals(0, count(jdbc, "iam.sessions", "revoked_at IS NOT NULL", second.sessionId()));
        assertEquals(1, count(jdbc, "iam.refresh_credentials", "revoked_at IS NOT NULL",
            first.credentialId()));
        assertEquals(1, count(jdbc, "iam.outbox_events", "event_type = 'SessionRevoked'",
            first.sessionId()));
        assertThrows(InvalidLoginException.class,
            () -> service.logout(first.raw(), true, UUID.randomUUID()));

        service.logout(second.raw(), true, UUID.randomUUID());
        assertEquals(1, count(jdbc, "iam.sessions", "revoked_at IS NOT NULL", second.sessionId()));
        assertEquals(1, count(jdbc, "iam.refresh_token_families", "revoked_at IS NOT NULL",
            second.familyId()));
        assertEquals(1, count(jdbc, "iam.outbox_events", "event_type = 'SessionRevoked'",
            second.sessionId()));
        assertEquals(0, count(jdbc, "iam.sessions", "revoked_at IS NOT NULL", stranger.sessionId()));
    }

    @Test
    void outboxFailureRollsBackSessionAndFamilyRevocation() {
        var source = source();
        var jdbc = new JdbcTemplate(source);
        Fixture fixture = fixture(jdbc);
        var brokenJson = new ObjectMapper() {
            @Override
            public String writeValueAsString(Object value) throws JsonProcessingException {
                throw new JsonProcessingException("forced failure") { };
            }
        };
        assertThrows(IllegalStateException.class, () ->
            service(jdbc, source, brokenJson).logout(fixture.raw(), false, UUID.randomUUID()));
        assertEquals(0, count(jdbc, "iam.sessions", "revoked_at IS NOT NULL", fixture.sessionId()));
        assertEquals(0, count(jdbc, "iam.refresh_token_families", "revoked_at IS NOT NULL",
            fixture.familyId()));
        assertEquals(0, count(jdbc, "iam.outbox_events", "event_type = 'SessionRevoked'",
            fixture.sessionId()));
    }

    private static DriverManagerDataSource source() {
        return new DriverManagerDataSource(System.getenv("IAM_TEST_JDBC_URL"), "iam_runtime", "");
    }

    private static LogoutService service(JdbcTemplate jdbc, DriverManagerDataSource source,
                                         ObjectMapper json) {
        return new LogoutService(new JdbcLogoutUnitOfWork(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source)), json),
            TOKENS, Clock.systemUTC());
    }

    private static Fixture fixture(JdbcTemplate jdbc) {
        return fixture(jdbc, UUID.randomUUID());
    }

    private static Fixture fixture(JdbcTemplate jdbc, UUID user) {
        UUID session = UUID.randomUUID();
        UUID family = UUID.randomUUID();
        UUID credential = UUID.randomUUID();
        String raw = UUID.randomUUID().toString();
        Instant created = Instant.now().minusSeconds(60);
        Integer userExists = jdbc.queryForObject(
            "SELECT count(*) FROM iam.users WHERE user_id = ?", Integer.class, user);
        if (userExists == 0) jdbc.update("""
            INSERT INTO iam.users (user_id,email,password_hash,status,email_verified_at,
                                   created_at,updated_at)
            VALUES (?,?,'test-hash','ACTIVE',?,?,?)
            """, user, user + "@example.test", Timestamp.from(created),
            Timestamp.from(created), Timestamp.from(created));
        jdbc.update("""
            INSERT INTO iam.sessions (session_id,user_id,created_at,last_user_activity_at,
                                      inactivity_expires_at)
            VALUES (?,?,?,?,?)
            """, session, user, Timestamp.from(created), Timestamp.from(created),
            Timestamp.from(created.plusSeconds(86400)));
        jdbc.update("INSERT INTO iam.refresh_token_families "
            + "(family_id,session_id,created_at) VALUES (?,?,?)",
            family, session, Timestamp.from(created));
        jdbc.update("""
            INSERT INTO iam.refresh_credentials
              (credential_id,family_id,token_hash,issued_at,expires_at)
            VALUES (?,?,?,?,?)
            """, credential, family, TOKENS.hash(raw), Timestamp.from(created),
            Timestamp.from(created.plusSeconds(86400)));
        return new Fixture(user, session, family, credential, raw);
    }

    private static int count(JdbcTemplate jdbc, String table, String predicate, UUID id) {
        // Table names and predicates are fixed test literals, never request data.
        String key = table.equals("iam.sessions") ? "session_id"
            : table.equals("iam.refresh_token_families") ? "family_id"
            : table.equals("iam.refresh_credentials") ? "credential_id" : "aggregate_id";
        return jdbc.queryForObject("SELECT count(*) FROM " + table + " WHERE " + key
            + " = ? AND " + predicate, Integer.class, id);
    }

    private record Fixture(UUID userId, UUID sessionId, UUID familyId,
                           UUID credentialId, String raw) { }
}
