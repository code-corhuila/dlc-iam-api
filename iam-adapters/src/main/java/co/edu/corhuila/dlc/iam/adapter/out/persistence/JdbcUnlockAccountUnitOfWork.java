package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.UnlockAccountUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public class JdbcUnlockAccountUnitOfWork implements UnlockAccountUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcUnlockAccountUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
                                       ObjectMapper json) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.json = json;
    }

    @Override
    public <T> T execute(Function<Store, T> operation) {
        try {
            return transactions.execute(status -> operation.apply(new JdbcStore()));
        } catch (DuplicateKeyException duplicate) {
            throw new ConcurrentModificationException("Unlock request key already used");
        }
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
        public Attempt findAttempt(UUID idempotencyKey) {
            var rows = jdbc.query("""
                SELECT actor_user_id, user_id, reason, expected_version
                  FROM iam.account_lock_audit
                 WHERE idempotency_key = ? AND action = 'UNLOCKED'
                """, (rs, row) -> new Attempt(rs.getObject("actor_user_id", UUID.class),
                    rs.getObject("user_id", UUID.class), rs.getString("reason"),
                    rs.getLong("expected_version"), rs.getLong("expected_version") + 1),
                idempotencyKey);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public Account findForUpdate(UUID userId) {
            var rows = jdbc.query("""
                SELECT user_id, email, display_name, status, created_at, updated_at,
                       email_verified_at IS NOT NULL AS verified, version
                  FROM iam.users WHERE user_id = ? FOR UPDATE
                """, (rs, row) -> new Account(rs.getObject("user_id", UUID.class),
                    rs.getString("email"), rs.getString("display_name"),
                    jdbc.queryForList("SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role",
                        String.class, userId), rs.getString("status"),
                    rs.getTimestamp("created_at").toInstant(),
                    rs.getTimestamp("updated_at").toInstant(),
                    rs.getBoolean("verified"), rs.getLong("version")),
                userId);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public void unlock(UUID userId, long expectedVersion, Instant at) {
            int changed = jdbc.update("""
                UPDATE iam.users SET status = 'ACTIVE', failed_attempts = 0,
                    locked_until = NULL, updated_at = ?, version = version + 1
                 WHERE user_id = ? AND version = ? AND status = 'LOCKED'
                   AND email_verified_at IS NOT NULL
                """, Timestamp.from(at), userId, expectedVersion);
            if (changed != 1) throw new ConcurrentModificationException("Staff version changed");
        }

        @Override
        public void appendAudit(UUID userId, UUID actorId, String reason,
                                long expectedVersion, long resultVersion,
                                UUID idempotencyKey, UUID correlationId, Instant at) {
            if (resultVersion != expectedVersion + 1) {
                throw new IllegalArgumentException("Invalid unlock result version");
            }
            jdbc.update("""
                INSERT INTO iam.account_lock_audit
                  (audit_id, user_id, action, actor_user_id, failed_attempts,
                   occurred_at, correlation_id, reason, idempotency_key, expected_version)
                VALUES (?, ?, 'UNLOCKED', ?, 0, ?, ?, ?, ?, ?)
                """, UUID.randomUUID(), userId, actorId, Timestamp.from(at),
                correlationId, reason, idempotencyKey, expectedVersion);
        }

        @Override
        public void appendUserUnlocked(UUID userId, UUID actorId, UUID idempotencyKey,
                                       UUID correlationId, Instant at) {
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "userId", userId.toString(), "unlockedAt", at.toString(),
                    "mode", "ADMINISTRATOR", "performedBy", actorId.toString()));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize UserUnlocked", failure);
            }
            jdbc.update("""
                INSERT INTO iam.outbox_events
                  (event_id,event_type,aggregate_id,correlation_id,causation_id,payload,occurred_at)
                VALUES (?,'UserUnlocked',?,?,?,?::jsonb,?)
                """, UUID.randomUUID(), userId, correlationId, idempotencyKey,
                payload, Timestamp.from(at));
        }
    }
}
