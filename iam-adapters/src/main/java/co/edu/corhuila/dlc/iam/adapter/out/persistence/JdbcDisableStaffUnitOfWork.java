package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.DisableStaffUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcDisableStaffUnitOfWork implements DisableStaffUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcDisableStaffUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
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
                SELECT action,actor_user_id,user_id,reason,expected_version
                  FROM iam.staff_account_audit
                 WHERE idempotency_key = ?
                """, (rs, row) -> {
                    if (!"DISABLED".equals(rs.getString(1))) {
                        throw new ConcurrentModificationException("Idempotency key reused");
                    }
                    long version = rs.getLong(5);
                    return new Attempt(rs.getObject(2, UUID.class),
                        rs.getObject(3, UUID.class), rs.getString(4), version, version + 1);
                }, key);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public Account findForUpdate(UUID userId) {
            var rows = jdbc.query("""
                SELECT user_id,email,display_name,status,version,created_at,updated_at
                  FROM iam.users WHERE user_id = ? FOR UPDATE
                """, (rs, row) -> new Account(rs.getObject(1, UUID.class), rs.getString(2),
                rs.getString(3), rs.getString(4), rs.getLong(5), jdbc.queryForList(
                    "SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role",
                    String.class, userId), rs.getTimestamp(6).toInstant(),
                rs.getTimestamp(7).toInstant()), userId);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public List<UUID> activeSessionsForUpdate(UUID userId) {
            return jdbc.query("""
                SELECT session_id FROM iam.sessions WHERE user_id = ? AND revoked_at IS NULL
                 ORDER BY session_id FOR UPDATE
                """, (rs, row) -> rs.getObject(1, UUID.class), userId);
        }

        @Override
        public void disable(UUID userId, long expectedVersion, Instant at) {
            int updated = jdbc.update("""
                UPDATE iam.users SET status = 'DISABLED', failed_attempts = 0,
                    locked_until = NULL, version = version + 1, updated_at = ?
                 WHERE user_id = ? AND version = ? AND status <> 'DISABLED'
                """, Timestamp.from(at), userId, expectedVersion);
            if (updated != 1) throw new ConcurrentModificationException("Staff version changed");
            // The database's status trigger revokes sessions and refresh lineage in this transaction.
        }

        @Override
        public void appendAudit(UUID userId, UUID actorId, String priorStatus, String reason,
                                long expectedVersion, UUID key, UUID correlationId, Instant at) {
            jdbc.update("""
                INSERT INTO iam.staff_account_audit
                  (audit_id,user_id,action,actor_user_id,prior_status,next_status,occurred_at,
                   correlation_id,reason,idempotency_key,expected_version)
                VALUES (?,?,'DISABLED',?,?,'DISABLED',?,?,?,?,?)
                """, UUID.randomUUID(), userId, actorId, priorStatus, Timestamp.from(at),
                correlationId, reason, key, expectedVersion);
        }

        @Override
        public void appendSessionRevoked(UUID sessionId, UUID userId, UUID actorId,
                                         UUID correlationId, Instant at) {
            try {
                String payload = json.writeValueAsString(Map.of(
                    "sessionId", sessionId.toString(), "userId", userId.toString(),
                    "reason", "ACCOUNT_DISABLED", "revokedAt", at.toString()));
                jdbc.update("""
                    INSERT INTO iam.outbox_events
                      (event_id,event_type,aggregate_id,correlation_id,causation_id,payload,occurred_at)
                    VALUES (?,'SessionRevoked',?,?,?,?::jsonb,?)
                    """, UUID.randomUUID(), sessionId, correlationId, correlationId,
                    payload, Timestamp.from(at));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize approved event", failure);
            }
        }
    }
}
