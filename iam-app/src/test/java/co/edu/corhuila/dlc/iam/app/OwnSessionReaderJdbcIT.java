package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcOwnSessionReader;
import co.edu.corhuila.dlc.iam.application.usecase.ListOwnSessionsService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/** Run against a disposable IAM database with migration 011, as iam_runtime. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class OwnSessionReaderJdbcIT {
    @Test
    void returnsOnlyOwnerSessionsInStablePagesIncludingVersion() {
        var source = new DriverManagerDataSource(System.getenv("IAM_TEST_JDBC_URL"),
            "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var service = new ListOwnSessionsService(new JdbcOwnSessionReader(jdbc,
            new DataSourceTransactionManager(source)));
        UUID owner = UUID.randomUUID();
        UUID stranger = UUID.randomUUID();
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        Instant created = Instant.now().minusSeconds(120);
        insertUser(jdbc, owner, created);
        insertUser(jdbc, stranger, created);
        insertSession(jdbc, first, owner, created, null);
        insertSession(jdbc, second, owner, created.plusSeconds(1), "browser");
        insertSession(jdbc, UUID.randomUUID(), stranger, created, "other");

        var page1 = service.list(owner, second, 1, 1);
        assertEquals(2, page1.meta().total());
        assertEquals(2, page1.meta().totalPages());
        assertEquals(first, page1.data().getFirst().id());
        assertEquals(false, page1.data().getFirst().current());
        assertEquals(null, page1.data().getFirst().device());
        assertEquals(1, page1.data().getFirst().version());

        var page2 = service.list(owner, second, 2, 1);
        assertEquals(second, page2.data().getFirst().id());
        assertEquals(true, page2.data().getFirst().current());
        assertEquals("browser", page2.data().getFirst().device());
        assertEquals(0, service.list(owner, second, 3, 1).data().size());
        assertEquals(0, service.list(UUID.randomUUID(), second, 1, 20).meta().total());
    }

    private static void insertUser(JdbcTemplate jdbc, UUID id, Instant created) {
        jdbc.update("""
            INSERT INTO iam.users (user_id,email,password_hash,status,email_verified_at,
                                   created_at,updated_at)
            VALUES (?,?,'test-hash','ACTIVE',?,?,?)
            """, id, id + "@example.test", Timestamp.from(created),
            Timestamp.from(created), Timestamp.from(created));
    }

    private static void insertSession(JdbcTemplate jdbc, UUID id, UUID user,
                                      Instant created, String device) {
        jdbc.update("""
            INSERT INTO iam.sessions (session_id,user_id,device_id,created_at,
                                      last_user_activity_at,inactivity_expires_at)
            VALUES (?,?,?,?,?,?)
            """, id, user, device, Timestamp.from(created), Timestamp.from(created),
            Timestamp.from(created.plusSeconds(3600)));
    }
}
