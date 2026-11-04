package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.StaffNameUnitOfWork;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcStaffNameUnitOfWork implements StaffNameUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public JdbcStaffNameUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public <T> T execute(Function<Store, T> operation) {
        return transactions.execute(status -> operation.apply(new JdbcStore()));
    }

    private final class JdbcStore implements Store {
        @Override
        public boolean activeAdministrator(UUID actorId) {
            var matches = jdbc.query("""
                SELECT u.user_id FROM iam.users u JOIN iam.user_roles r ON r.user_id = u.user_id
                 WHERE u.user_id = ? AND u.status = 'ACTIVE' AND u.email_verified_at IS NOT NULL
                   AND r.role = 'ADMINISTRATOR'
                 FOR UPDATE OF u
                """, (rs, row) -> rs.getObject(1, UUID.class), actorId);
            return !matches.isEmpty();
        }

        @Override
        public Staff findForUpdate(UUID userId) {
            var rows = jdbc.query("""
                SELECT user_id, email, display_name, status, created_at, updated_at, version
                  FROM iam.users
                 WHERE user_id = ? FOR UPDATE
                """, (rs, row) -> new Staff(rs.getObject("user_id", UUID.class),
                    rs.getString("email"), rs.getString("display_name"),
                    jdbc.queryForList("""
                        SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role
                        """, String.class, userId), rs.getString("status"),
                    rs.getTimestamp("created_at").toInstant(),
                    rs.getTimestamp("updated_at").toInstant(), rs.getLong("version")), userId);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public void updateName(UUID userId, String name, long expectedVersion, Instant at) {
            int changed = jdbc.update("""
                UPDATE iam.users SET display_name = ?, version = version + 1, updated_at = ?
                 WHERE user_id = ? AND version = ?
                """, name, Timestamp.from(at), userId, expectedVersion);
            if (changed != 1) {
                throw new IllegalStateException("Staff update lost its row lock");
            }
        }

        @Override
        public void appendAudit(UUID userId, UUID actorId, String status,
                                UUID correlationId, Instant at) {
            jdbc.update("""
                INSERT INTO iam.staff_account_audit
                  (audit_id, user_id, action, actor_user_id, prior_status,
                   next_status, occurred_at, correlation_id)
                VALUES (?, ?, 'UPDATED', ?, ?, ?, ?, ?)
                """, UUID.randomUUID(), userId, actorId, status, status,
                Timestamp.from(at), correlationId);
        }
    }
}
