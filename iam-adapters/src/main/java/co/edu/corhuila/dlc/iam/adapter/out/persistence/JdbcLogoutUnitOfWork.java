package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.LogoutUnitOfWork;
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
public class JdbcLogoutUnitOfWork implements LogoutUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcLogoutUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
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
        public Credential findForUpdate(String tokenHash) {
            var keys = jdbc.query("""
                SELECT u.user_id, s.session_id, f.family_id, c.credential_id
                  FROM iam.refresh_credentials c
                  JOIN iam.refresh_token_families f ON f.family_id = c.family_id
                  JOIN iam.sessions s ON s.session_id = f.session_id
                  JOIN iam.users u ON u.user_id = s.user_id
                 WHERE c.token_hash = ?
                """, (rs, row) -> new Keys(rs.getObject(1, UUID.class),
                    rs.getObject(2, UUID.class), rs.getObject(3, UUID.class),
                    rs.getObject(4, UUID.class)), tokenHash);
            if (keys.isEmpty()) return null;
            Keys key = keys.getFirst();
            // Match login, disable and rotation order: user, session, family, credential.
            var users = jdbc.query("SELECT user_id FROM iam.users WHERE user_id = ? FOR UPDATE",
                (rs, row) -> rs.getObject(1, UUID.class), key.userId());
            var sessions = jdbc.query("""
                SELECT revoked_at, inactivity_expires_at FROM iam.sessions
                 WHERE session_id = ? AND user_id = ? FOR UPDATE
                """, (rs, row) -> new Session(instant(rs.getTimestamp(1)),
                    rs.getTimestamp(2).toInstant()), key.sessionId(), key.userId());
            var families = jdbc.query("""
                SELECT revoked_at FROM iam.refresh_token_families
                 WHERE family_id = ? AND session_id = ? FOR UPDATE
                """, (rs, row) -> instant(rs.getTimestamp(1)),
                key.familyId(), key.sessionId());
            var credentials = jdbc.query("""
                SELECT expires_at, consumed_at, revoked_at FROM iam.refresh_credentials
                 WHERE credential_id = ? AND family_id = ? AND token_hash = ? FOR UPDATE
                """, (rs, row) -> new State(rs.getTimestamp(1).toInstant(),
                    instant(rs.getTimestamp(2)), instant(rs.getTimestamp(3))),
                key.credentialId(), key.familyId(), tokenHash);
            if (users.isEmpty() || sessions.isEmpty() || families.isEmpty()
                || credentials.isEmpty()) return null;
            Session session = sessions.getFirst();
            State credential = credentials.getFirst();
            return new Credential(key.userId(), key.sessionId(), credential.expiresAt(),
                credential.consumedAt(), credential.revokedAt(), families.getFirst(),
                session.revokedAt(), session.inactivityExpiresAt());
        }

        @Override
        public List<UUID> activeSessionsForUpdate(UUID userId, UUID currentId,
                                                   boolean allDevices) {
            return jdbc.query("""
                SELECT session_id FROM iam.sessions
                 WHERE user_id = ? AND revoked_at IS NULL
                   AND inactivity_expires_at > statement_timestamp()
                   AND (? OR session_id = ?)
                 ORDER BY session_id FOR UPDATE
                """, (rs, row) -> rs.getObject(1, UUID.class),
                userId, allDevices, currentId);
        }

        @Override
        public boolean revokeSession(UUID userId, UUID sessionId, Instant at) {
            // DB triggers revoke the linked refresh family and credentials.
            return jdbc.update("""
                UPDATE iam.sessions SET revoked_at = ?, revocation_reason = 'LOGOUT'
                 WHERE user_id = ? AND session_id = ? AND revoked_at IS NULL
                """, Timestamp.from(at), userId, sessionId) == 1;
        }

        @Override
        public void appendSessionRevoked(UUID eventId, UUID userId, UUID sessionId,
                                         UUID correlationId, Instant at) {
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "sessionId", sessionId.toString(), "userId", userId.toString(),
                    "reason", "LOGOUT", "revokedAt", at.toString()));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize SessionRevoked", failure);
            }
            jdbc.update("""
                INSERT INTO iam.outbox_events
                  (event_id, event_type, aggregate_id, correlation_id,
                   causation_id, payload, occurred_at)
                VALUES (?, 'SessionRevoked', ?, ?, ?, ?::jsonb, ?)
                """, eventId, sessionId, correlationId, correlationId,
                payload, Timestamp.from(at));
        }
    }

    private static Instant instant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }

    private record Keys(UUID userId, UUID sessionId, UUID familyId, UUID credentialId) { }
    private record Session(Instant revokedAt, Instant inactivityExpiresAt) { }
    private record State(Instant expiresAt, Instant consumedAt, Instant revokedAt) { }
}
