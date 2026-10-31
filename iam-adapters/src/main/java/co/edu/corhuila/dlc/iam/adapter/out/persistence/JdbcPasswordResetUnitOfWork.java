package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.PasswordResetUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcPasswordResetUnitOfWork implements PasswordResetUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcPasswordResetUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
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
        public Challenge findForUpdate(String tokenHash, String purpose) {
            var rows = jdbc.query("""
                SELECT challenge_id, user_id, purpose, expires_at, consumed_at
                  FROM iam.security_challenges
                 WHERE token_hash = ? AND purpose = ? FOR UPDATE
                """, (rs, row) -> new Challenge(
                    rs.getObject("challenge_id", UUID.class),
                    rs.getObject("user_id", UUID.class), rs.getString("purpose"),
                    rs.getTimestamp("expires_at").toInstant(),
                    instantOrNull(rs.getTimestamp("consumed_at"))), tokenHash, purpose);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public boolean consume(UUID challengeId, Instant at) {
            return jdbc.update("""
                UPDATE iam.security_challenges SET consumed_at = ?
                 WHERE challenge_id = ? AND purpose = 'PASSWORD_RECOVERY'
                   AND consumed_at IS NULL AND expires_at > ?
                """, Timestamp.from(at), challengeId, Timestamp.from(at)) == 1;
        }

        @Override
        public boolean changePassword(UUID userId, String passwordHash, Instant at) {
            return jdbc.update("""
                UPDATE iam.users SET password_hash = ?, updated_at = ?, version = version + 1
                 WHERE user_id = ?
                """, passwordHash, Timestamp.from(at), userId) == 1;
        }

        @Override
        public void revokeSessions(UUID userId, UUID correlationId, Instant at) {
            var sessionIds = jdbc.queryForList("""
                SELECT session_id FROM iam.sessions
                 WHERE user_id = ? AND revoked_at IS NULL FOR UPDATE
                """, UUID.class, userId);
            for (UUID sessionId : sessionIds) {
                if (jdbc.update("""
                    UPDATE iam.sessions SET revoked_at = ?, revocation_reason = 'PASSWORD_RESET'
                     WHERE session_id = ? AND user_id = ? AND revoked_at IS NULL
                    """, Timestamp.from(at), sessionId, userId) != 1) {
                    throw new IllegalStateException("Session changed during password reset");
                }
                appendSessionRevoked(sessionId, userId, correlationId, at);
            }
        }

        private void appendSessionRevoked(UUID sessionId, UUID userId,
                                          UUID correlationId, Instant at) {
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "sessionId", sessionId.toString(), "userId", userId.toString(),
                    "reason", "PASSWORD_RESET", "revokedAt", at.toString()));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize owner event", failure);
            }
            jdbc.update("""
                INSERT INTO iam.outbox_events
                  (event_id, event_type, aggregate_id, correlation_id,
                   causation_id, payload, occurred_at)
                VALUES (?, 'SessionRevoked', ?, ?, ?, ?::jsonb, ?)
                """, UUID.randomUUID(), sessionId, correlationId, correlationId,
                payload, Timestamp.from(at));
        }
    }

    private static Instant instantOrNull(Timestamp value) {
        return value == null ? null : value.toInstant();
    }
}
