package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcRoleAssignmentUnitOfWork;
import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcSessionSnapshotReader;
import co.edu.corhuila.dlc.iam.application.usecase.ReplaceRoleAssignmentsService;
import co.edu.corhuila.dlc.iam.application.usecase.ValidateSessionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Run against a disposable IAM DB with display-name and audit-reason migrations. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class RoleAssignmentJdbcIT {
    @Test
    void changesOnlyRoleDeltaAndAtomicallyAuditsRevokesAndEmits() {
        String url = System.getenv("IAM_TEST_JDBC_URL");
        var source = new DriverManagerDataSource(url, "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var adminJdbc = new JdbcTemplate(new DriverManagerDataSource(url, "postgres", ""));
        var service = new ReplaceRoleAssignmentsService(
            new JdbcRoleAssignmentUnitOfWork(jdbc,
                new TransactionTemplate(new DataSourceTransactionManager(source)),
                new ObjectMapper()), Clock.systemUTC());
        UUID admin = UUID.randomUUID();
        UUID staff = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        UUID family = UUID.randomUUID();
        UUID credential = UUID.randomUUID();
        UUID correlation = UUID.randomUUID();
        Instant created = Instant.now().minusSeconds(60);
        for (UUID id : new UUID[] {admin, staff}) {
            jdbc.update("""
                INSERT INTO iam.users
                  (user_id,email,display_name,password_hash,status,email_verified_at,
                   created_at,updated_at,version)
                VALUES (?,?,?,'test-hash','ACTIVE',?,?,?,1)
                """, id, id + "@example.test", "Test Staff", Timestamp.from(created),
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
        var validation = new ValidateSessionService(new JdbcSessionSnapshotReader(jdbc),
            Clock.systemUTC());
        assertTrue(validation.active(staff, session, List.of("DENTIST")));

        adminJdbc.execute("REVOKE INSERT ON iam.outbox_events FROM iam_runtime");
        try {
            assertThrows(DataAccessException.class,
                () -> service.replace(admin, staff, List.of("SECRETARY_ASSISTANT"),
                    1, "Duty change", correlation));
            assertEquals(1, jdbc.queryForObject(
                "SELECT version FROM iam.users WHERE user_id = ?", Long.class, staff));
            assertEquals(List.of("DENTIST"), jdbc.queryForList(
                "SELECT role FROM iam.user_roles WHERE user_id = ?", String.class, staff));
            assertEquals(0, count(jdbc, "iam.role_assignment_audit", staff, "user_id"));
            assertEquals(0, count(jdbc, "iam.outbox_events", staff, "aggregate_id"));
        } finally {
            adminJdbc.execute("GRANT INSERT ON iam.outbox_events TO iam_runtime");
        }

        var result = service.replace(admin, staff, List.of("SECRETARY_ASSISTANT"),
            1, "Duty change", correlation);
        assertEquals(2, result.version());
        assertEquals(List.of("SECRETARY_ASSISTANT"), result.roles());
        assertEquals(List.of("SECRETARY_ASSISTANT"), jdbc.queryForList(
            "SELECT role FROM iam.user_roles WHERE user_id = ?", String.class, staff));
        assertEquals(2, jdbc.queryForObject("""
            SELECT count(*) FROM iam.role_assignment_audit
             WHERE user_id = ? AND actor_user_id = ? AND reason = ? AND correlation_id = ?
            """, Integer.class, staff, admin, "Duty change", correlation));
        assertEquals(1, count(jdbc, "iam.outbox_events", session, "aggregate_id"));
        assertEquals(2, count(jdbc, "iam.outbox_events", staff, "aggregate_id"));
        assertEquals(1, jdbc.queryForObject("""
            SELECT count(*) FROM iam.outbox_events
             WHERE aggregate_id = ? AND event_type = 'RoleAssignedToUser'
               AND payload ->> 'role' = 'SECRETARY_ASSISTANT'
               AND payload ->> 'assignedBy' = ? AND NOT jsonb_exists(payload, 'reason')
            """, Integer.class, staff, admin.toString()));
        assertEquals(1, jdbc.queryForObject("""
            SELECT count(*) FROM iam.outbox_events
             WHERE aggregate_id = ? AND event_type = 'RoleRevokedFromUser'
               AND payload ->> 'role' = 'DENTIST'
               AND payload ->> 'revokedBy' = ? AND NOT jsonb_exists(payload, 'reason')
            """, Integer.class, staff, admin.toString()));
        assertEquals(1, jdbc.queryForObject(
            "SELECT count(*) FROM iam.sessions WHERE session_id = ? AND revoked_at IS NOT NULL",
            Integer.class, session));
        assertFalse(validation.active(staff, session, List.of("DENTIST")));
        assertEquals(1, jdbc.queryForObject(
            "SELECT count(*) FROM iam.refresh_credentials WHERE credential_id = ? AND revoked_at IS NOT NULL",
            Integer.class, credential));
        service.replace(admin, staff, List.of("SECRETARY_ASSISTANT"),
            2, "No change", UUID.randomUUID());
        assertEquals(2, count(jdbc, "iam.role_assignment_audit", staff, "user_id"));
        assertEquals(2, count(jdbc, "iam.outbox_events", staff, "aggregate_id"));
        assertThrows(ConcurrentModificationException.class,
            () -> service.replace(admin, staff, List.of("DENTIST"),
                1, "Stale", UUID.randomUUID()));

        UUID second = UUID.randomUUID();
        jdbc.update("""
            INSERT INTO iam.users
              (user_id,email,display_name,password_hash,status,email_verified_at,
               created_at,updated_at,version)
            VALUES (?,?,?,'test-hash','ACTIVE',?,?,?,1)
            """, second, second + "@example.test", "Other Staff", Timestamp.from(created),
            Timestamp.from(created), Timestamp.from(created));
        for (String role : List.of("DENTIST", "SECRETARY_ASSISTANT")) {
            jdbc.update("INSERT INTO iam.user_roles (user_id,role,assigned_at) VALUES (?,?,?)",
                second, role, Timestamp.from(created));
        }
        Timestamp originalAssignment = jdbc.queryForObject("""
            SELECT assigned_at FROM iam.user_roles WHERE user_id = ? AND role = 'DENTIST'
            """, Timestamp.class, second);
        service.replace(admin, second, List.of("DENTIST"), 1, "Narrow duties", UUID.randomUUID());
        assertEquals(originalAssignment, jdbc.queryForObject("""
            SELECT assigned_at FROM iam.user_roles WHERE user_id = ? AND role = 'DENTIST'
            """, Timestamp.class, second));
    }

    private static int count(JdbcTemplate jdbc, String table, UUID id, String column) {
        // Table and column are fixed literals in this test, never request data.
        return jdbc.queryForObject("SELECT count(*) FROM " + table + " WHERE " + column + " = ?",
            Integer.class, id);
    }
}
