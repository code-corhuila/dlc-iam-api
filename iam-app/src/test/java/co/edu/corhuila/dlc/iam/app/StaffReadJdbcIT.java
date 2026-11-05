package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcStaffReader;
import co.edu.corhuila.dlc.iam.application.usecase.ReadStaffService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Exercise staff reads with the IAM runtime role against a disposable migrated database. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class StaffReadJdbcIT {
    @Test
    void readsOnlyApprovedFieldsWithStablePagesAndOwnerPrivileges() {
        String url = System.getenv("IAM_TEST_JDBC_URL");
        var source = new DriverManagerDataSource(url, "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var owner = new JdbcTemplate(new DriverManagerDataSource(url, "postgres", ""));
        var service = new ReadStaffService(new JdbcStaffReader(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source))));
        Instant created = Instant.now().minusSeconds(60);
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        UUID third = UUID.randomUUID();
        // Equal timestamps prove the id tie-breaker, independent of insertion order.
        var ids = new java.util.ArrayList<>(List.of(first, second));
        ids.sort(UUID::compareTo);
        insert(jdbc, ids.get(1), "Second Staff", created, "DENTIST");
        insert(jdbc, ids.get(0), "First Staff", created, "SECRETARY_ASSISTANT");
        insert(jdbc, third, "Later Staff", created.plusSeconds(1), "DENTIST");

        var page1 = service.list(1, 1);
        assertEquals(3, page1.meta().total());
        assertEquals(3, page1.meta().totalPages());
        assertEquals(ids.get(0), page1.data().getFirst().id());
        assertEquals(List.of("SECRETARY_ASSISTANT"), page1.data().getFirst().roles());
        assertEquals(ids.get(1), service.list(2, 1).data().getFirst().id());
        assertEquals(third, service.list(3, 1).data().getFirst().id());
        assertEquals(List.of(), service.list(4, 1).data());
        assertEquals("First Staff", service.read(ids.get(0)).name());
        assertEquals(1, service.read(ids.get(0)).version());
        assertThrows(java.util.NoSuchElementException.class, () -> service.read(UUID.randomUUID()));

        UUID legacy = UUID.randomUUID();
        jdbc.update("""
            INSERT INTO iam.users (user_id,email,password_hash,status,email_verified_at,
                                   created_at,updated_at,version)
            VALUES (?,?,'secret-hash','ACTIVE',?,?,?,1)
            """, legacy, legacy + "@example.test", Timestamp.from(created),
            Timestamp.from(created), Timestamp.from(created));
        assertThrows(IllegalStateException.class, () -> service.read(legacy));

        owner.execute("CREATE SCHEMA staff_read_other_owner");
        owner.execute("CREATE TABLE staff_read_other_owner.secret (value text)");
        try {
            assertThrows(DataAccessException.class,
                () -> jdbc.queryForObject("SELECT count(*) FROM staff_read_other_owner.secret", Integer.class));
        } finally {
            owner.execute("DROP SCHEMA staff_read_other_owner CASCADE");
        }
    }

    private static void insert(JdbcTemplate jdbc, UUID id, String name, Instant at, String role) {
        jdbc.update("""
            INSERT INTO iam.users (user_id,email,display_name,password_hash,status,
                                   email_verified_at,created_at,updated_at,version)
            VALUES (?,?,?,'secret-hash','ACTIVE',?,?,?,1)
            """, id, id + "@example.test", name, Timestamp.from(at),
            Timestamp.from(at), Timestamp.from(at));
        jdbc.update("INSERT INTO iam.user_roles (user_id,role,assigned_at) VALUES (?,?,?)",
            id, role, Timestamp.from(at));
    }
}
