package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.UnlockUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public class JdbcUnlockUnitOfWork implements UnlockUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcUnlockUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
                                ObjectMapper json) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.json = json;
    }

    @Override
    public <T> T execute(Function<Store, T> operation) {
        return transactions.execute(status -> operation.apply(new JdbcStore()));
    }

    private final class JdbcStore implements Store {
        @Override
        public boolean isCurrentAdministrator(UUID actorId, UUID sessionId, Instant now) {
            // Lock the actor and session until commit. The ordinary role flow
            // cannot revoke the bootstrap Administrator role.
            return !jdbc.queryForList("""
                SELECT u.user_id FROM iam.users u
                  JOIN iam.sessions s ON s.user_id = u.user_id
                  JOIN iam.user_roles r ON r.user_id = u.user_id
                 WHERE u.user_id = ? AND s.session_id = ?
                   AND u.status = 'ACTIVE' AND u.email_verified_at IS NOT NULL
                   AND s.revoked_at IS NULL AND s.inactivity_expires_at > ?
                   AND r.role = 'ADMINISTRATOR'
                 FOR SHARE OF u, s
                """, UUID.class, actorId, sessionId, Timestamp.from(now)).isEmpty();
        }

        @Override
        public Staff findForUpdate(UUID userId) {
            var users = jdbc.query("""
                SELECT user_id, email, display_name, status, version
                  FROM iam.users WHERE user_id = ? FOR UPDATE
                """, (rs, row) -> new Staff(rs.getObject("user_id", UUID.class),
                    rs.getString("email"), rs.getString("display_name"),
                    rs.getString("status"), rs.getLong("version"),
                    jdbc.queryForList("SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role",
                        String.class, userId)), userId);
            return users.isEmpty() ? null : users.getFirst();
        }

        @Override
        public void unlock(Staff staff, UUID actorId, UUID correlationId, Instant now) {
            jdbc.update("""
                UPDATE iam.users SET status = 'ACTIVE', failed_attempts = 0,
                  locked_until = NULL, updated_at = ?, version = version + 1
                 WHERE user_id = ? AND status = 'LOCKED'
                """, Timestamp.from(now), staff.id());
            jdbc.update("""
                INSERT INTO iam.account_lock_audit
                  (audit_id, user_id, action, actor_user_id, failed_attempts,
                   occurred_at, correlation_id, unlock_source)
                VALUES (?, ?, 'UNLOCKED', ?, 0, ?, ?, 'ADMINISTRATOR')
                """, UUID.randomUUID(), staff.id(), actorId,
                Timestamp.from(now), correlationId);
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "userId", staff.id().toString(), "unlockedAt", now.toString(),
                    "mode", "ADMINISTRATOR", "performedBy", actorId.toString()));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize owner event", failure);
            }
            jdbc.update("""
                INSERT INTO iam.outbox_events
                  (event_id, event_type, aggregate_id, correlation_id,
                   causation_id, payload, occurred_at)
                VALUES (?, 'UserUnlocked', ?, ?, ?, ?::jsonb, ?)
                """, UUID.randomUUID(), staff.id(), correlationId, correlationId,
                payload, Timestamp.from(now));
        }
    }
}
