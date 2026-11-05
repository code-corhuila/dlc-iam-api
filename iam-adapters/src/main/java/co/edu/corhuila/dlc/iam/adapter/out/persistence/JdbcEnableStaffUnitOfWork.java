package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.EnableStaffUnitOfWork;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcEnableStaffUnitOfWork implements EnableStaffUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public JdbcEnableStaffUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public <T> T execute(Function<Store, T> operation) {
        return transactions.execute(status -> operation.apply(new JdbcStore()));
    }

    private final class JdbcStore implements Store {
        @Override
        public boolean activeAdministratorForUpdate(UUID actorId) {
            return !jdbc.query("""
                SELECT u.user_id FROM iam.users u JOIN iam.user_roles r ON r.user_id = u.user_id
                 WHERE u.user_id = ? AND u.status = 'ACTIVE' AND u.email_verified_at IS NOT NULL
                   AND r.role = 'ADMINISTRATOR' FOR UPDATE OF u
                """, (rs, row) -> rs.getObject(1, UUID.class), actorId).isEmpty();
        }

        @Override
        public Attempt findAttempt(UUID key) {
            var rows = jdbc.query("""
                SELECT action,actor_user_id,user_id,reason,expected_version,next_status
                  FROM iam.staff_account_audit WHERE idempotency_key = ?
                """, (rs, row) -> {
                    if (!"ENABLED".equals(rs.getString(1))) {
                        throw new ConcurrentModificationException("Idempotency key reused");
                    }
                    long version = rs.getLong(5);
                    return new Attempt(rs.getObject(2, UUID.class), rs.getObject(3, UUID.class),
                        rs.getString(4), version, rs.getString(6), version + 1);
                }, key);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public Account findForUpdate(UUID userId) {
            var rows = jdbc.query("""
                SELECT user_id,email,display_name,status,email_verified_at,created_at,updated_at,
                       version FROM iam.users
                 WHERE user_id = ? FOR UPDATE
                """, (rs, row) -> new Account(rs.getObject(1, UUID.class), rs.getString(2),
                rs.getString(3), rs.getString(4), rs.getTimestamp(5) != null,
                rs.getTimestamp(6).toInstant(), rs.getTimestamp(7).toInstant(), rs.getLong(8),
                jdbc.queryForList(
                    "SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role",
                    String.class, userId)), userId);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public void enable(UUID userId, long expectedVersion, String nextStatus, Instant at) {
            int updated = jdbc.update("""
                UPDATE iam.users SET status = ?, failed_attempts = 0, locked_until = NULL,
                    version = version + 1, updated_at = ?
                 WHERE user_id = ? AND version = ? AND status = 'DISABLED'
                """, nextStatus, Timestamp.from(at), userId, expectedVersion);
            if (updated != 1) throw new ConcurrentModificationException("Staff version changed");
        }

        @Override
        public void appendAudit(UUID userId, UUID actorId, String nextStatus, String reason,
                                long expectedVersion, UUID key, UUID correlationId, Instant at) {
            jdbc.update("""
                INSERT INTO iam.staff_account_audit
                  (audit_id,user_id,action,actor_user_id,prior_status,next_status,occurred_at,
                   correlation_id,reason,idempotency_key,expected_version)
                VALUES (?,?,'ENABLED',?,'DISABLED',?,?,?,?,?,?)
                """, UUID.randomUUID(), userId, actorId, nextStatus, Timestamp.from(at),
                correlationId, reason, key, expectedVersion);
        }
    }
}
