package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcStaffNameUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.UpdateStaffNameService;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Run against a disposable migrated IAM database as iam_runtime. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class StaffNameJdbcIT {
    @Test
    void authorizedUpdateIsVersionedAuditedAndOwnerScoped() {
        var source = new DriverManagerDataSource(System.getenv("IAM_TEST_JDBC_URL"),
            "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var service = new UpdateStaffNameService(new JdbcStaffNameUnitOfWork(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source))), Clock.systemUTC());
        UUID admin = UUID.randomUUID();
        UUID staff = UUID.randomUUID();
        UUID other = UUID.randomUUID();
        Instant created = Instant.now().minusSeconds(60);
        for (UUID id : new UUID[] {admin, staff, other}) {
            jdbc.update("""
                INSERT INTO iam.users
                  (user_id,email,password_hash,status,email_verified_at,created_at,updated_at,version)
                VALUES (?,?,'test-hash','ACTIVE',?,?,?,1)
                """, id, id + "@example.test", Timestamp.from(created),
                Timestamp.from(created), Timestamp.from(created));
        }
        jdbc.update("""
            INSERT INTO iam.user_roles (user_id,role,assigned_at)
            VALUES (?,'ADMINISTRATOR',?)
            """, admin, Timestamp.from(created));
        var correlation = UUID.randomUUID();
        assertThrows(SecurityException.class,
            () -> service.update(other, staff, "Ada Staff", 1, correlation));
        var updated = service.update(admin, staff, "Ada Staff", 1, correlation);
        assertEquals(2, updated.version());
        assertEquals("Ada Staff", jdbc.queryForObject(
            "SELECT display_name FROM iam.users WHERE user_id = ?", String.class, staff));
        assertEquals(1, jdbc.queryForObject("""
            SELECT count(*) FROM iam.staff_account_audit
             WHERE user_id = ? AND actor_user_id = ? AND correlation_id = ? AND action = 'UPDATED'
            """, Integer.class, staff, admin, correlation));
        assertThrows(ConcurrentModificationException.class,
            () -> service.update(admin, staff, "Second Name", 1, UUID.randomUUID()));
        service.update(admin, staff, "Ada Staff", 2, UUID.randomUUID());
        assertEquals(1, jdbc.queryForObject(
            "SELECT count(*) FROM iam.staff_account_audit WHERE user_id = ?",
            Integer.class, staff));
    }
}
