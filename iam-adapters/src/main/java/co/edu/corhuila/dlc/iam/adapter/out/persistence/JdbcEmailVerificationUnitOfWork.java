package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.EmailVerificationUnitOfWork;
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
public final class JdbcEmailVerificationUnitOfWork implements EmailVerificationUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcEmailVerificationUnitOfWork(JdbcTemplate jdbc,
                                           TransactionTemplate transactions, ObjectMapper json) {
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
                 WHERE challenge_id = ? AND purpose = 'EMAIL_VERIFICATION'
                   AND consumed_at IS NULL AND expires_at > ?
                """, Timestamp.from(at), challengeId, Timestamp.from(at)) == 1;
        }

        @Override
        public boolean activatePendingUser(UUID userId, Instant at) {
            return jdbc.update("""
                UPDATE iam.users SET status = 'ACTIVE', email_verified_at = ?,
                                     updated_at = ?, version = version + 1
                 WHERE user_id = ? AND status = 'PENDING_VERIFICATION'
                   AND email_verified_at IS NULL
                """, Timestamp.from(at), Timestamp.from(at), userId) == 1;
        }

        @Override
        public void appendUserEmailVerified(UUID eventId, UUID userId,
                                             UUID correlationId, Instant at) {
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "userId", userId.toString(), "verifiedAt", at.toString()));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize owner event", failure);
            }
            jdbc.update("""
                INSERT INTO iam.outbox_events
                  (event_id, event_type, aggregate_id, correlation_id,
                   causation_id, payload, occurred_at)
                VALUES (?, 'UserEmailVerified', ?, ?, ?, ?::jsonb, ?)
                """, eventId, userId, correlationId, correlationId,
                payload, Timestamp.from(at));
        }
    }

    private static Instant instantOrNull(Timestamp value) {
        return value == null ? null : value.toInstant();
    }
}
