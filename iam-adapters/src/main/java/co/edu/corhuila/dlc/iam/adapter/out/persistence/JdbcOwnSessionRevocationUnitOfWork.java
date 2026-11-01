package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionRevocationUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcOwnSessionRevocationUnitOfWork implements OwnSessionRevocationUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcOwnSessionRevocationUnitOfWork(JdbcTemplate jdbc,
                                              TransactionTemplate transactions, ObjectMapper json) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.json = json;
    }

    @Override
    public <T> T execute(Function<Store, T> operation) {
        try {
            return transactions.execute(status -> operation.apply(new JdbcStore()));
        } catch (DuplicateKeyException conflict) {
            throw new IllegalStateException("Idempotency key already used for another request", conflict);
        }
    }

    private final class JdbcStore implements Store {
        @Override
        public Attempt findAttempt(UUID eventId) {
            var rows = jdbc.query("""
                SELECT aggregate_id, payload ->> 'userId' AS owner_id,
                       payload ->> 'reason' AS reason
                  FROM iam.outbox_events
                 WHERE event_id = ? AND event_type = 'SessionRevoked'
                """, (rs, row) -> new Attempt(rs.getObject("aggregate_id", UUID.class),
                    UUID.fromString(rs.getString("owner_id")), rs.getString("reason")), eventId);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public Session findForUpdate(UUID sessionId, UUID ownerId) {
            var rows = jdbc.query("""
                SELECT revoked_at IS NOT NULL AS revoked FROM iam.sessions
                 WHERE session_id = ? AND user_id = ? FOR UPDATE
                """, (rs, row) -> new Session(rs.getBoolean("revoked")), sessionId, ownerId);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public boolean revoke(UUID sessionId, UUID ownerId, String reason, Instant at) {
            // The IAM DB trigger revokes the refresh family and credentials as part of this write.
            return jdbc.update("""
                UPDATE iam.sessions SET revoked_at = ?, revocation_reason = ?
                 WHERE session_id = ? AND user_id = ? AND revoked_at IS NULL
                """, Timestamp.from(at), reason, sessionId, ownerId) == 1;
        }

        @Override
        public void appendEvent(UUID eventId, UUID sessionId, UUID ownerId, String reason,
                                UUID correlationId, UUID idempotencyKey, Instant at) {
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "sessionId", sessionId.toString(), "userId", ownerId.toString(),
                    "reason", reason, "revokedAt", at.toString()));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize SessionRevoked", failure);
            }
            jdbc.update("""
                INSERT INTO iam.outbox_events
                  (event_id, event_type, aggregate_id, correlation_id,
                   causation_id, payload, occurred_at)
                VALUES (?, 'SessionRevoked', ?, ?, ?, ?::jsonb, ?)
                """, eventId, sessionId, correlationId, idempotencyKey,
                payload, Timestamp.from(at));
        }
    }
}
