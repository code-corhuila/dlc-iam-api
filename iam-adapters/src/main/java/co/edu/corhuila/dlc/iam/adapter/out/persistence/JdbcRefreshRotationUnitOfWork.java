package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshRotationUnitOfWork;
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
public final class JdbcRefreshRotationUnitOfWork implements RefreshRotationUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcRefreshRotationUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
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
            var matches = jdbc.query("""
                SELECT c.credential_id, f.family_id, s.session_id, u.user_id
                  FROM iam.refresh_credentials c
                  JOIN iam.refresh_token_families f ON f.family_id = c.family_id
                  JOIN iam.sessions s ON s.session_id = f.session_id
                  JOIN iam.users u ON u.user_id = s.user_id
                 WHERE c.token_hash = ?
                """, (rs, row) -> new Keys(rs.getObject(1, UUID.class),
                    rs.getObject(2, UUID.class), rs.getObject(3, UUID.class),
                    rs.getObject(4, UUID.class)), tokenHash);
            if (matches.isEmpty()) return null;
            Keys keys = matches.getFirst();
            // Match disable and role-change lock order: user, session, family, credential.
            var users = jdbc.query("""
                SELECT user_id, email, display_name, password_hash, status,
                       email_verified_at, failed_attempts, locked_until, version
                  FROM iam.users WHERE user_id = ? FOR UPDATE
                """, (rs, row) -> new LoginUnitOfWork.StaffAccount(
                    keys.userId(), rs.getString("email"), rs.getString("display_name"),
                    rs.getString("password_hash"), rs.getString("status"),
                    instant(rs.getTimestamp("email_verified_at")), rs.getInt("failed_attempts"),
                    instant(rs.getTimestamp("locked_until")), rs.getLong("version"),
                    jdbc.queryForList("SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role",
                        String.class, keys.userId())), keys.userId());
            if (users.isEmpty()) return null;
            var sessions = jdbc.query("""
                SELECT revoked_at, inactivity_expires_at FROM iam.sessions
                 WHERE session_id = ? AND user_id = ? FOR UPDATE
                """, (rs, row) -> new SessionState(instant(rs.getTimestamp(1)),
                    rs.getTimestamp(2).toInstant()), keys.sessionId(), keys.userId());
            var families = jdbc.query("""
                SELECT revoked_at FROM iam.refresh_token_families
                 WHERE family_id = ? AND session_id = ? FOR UPDATE
                """, (rs, row) -> instant(rs.getTimestamp(1)),
                keys.familyId(), keys.sessionId());
            var credentials = jdbc.query("""
                SELECT expires_at, consumed_at, revoked_at FROM iam.refresh_credentials
                 WHERE credential_id = ? AND family_id = ? AND token_hash = ? FOR UPDATE
                """, (rs, row) -> new CredentialState(rs.getTimestamp(1).toInstant(),
                    instant(rs.getTimestamp(2)), instant(rs.getTimestamp(3))),
                keys.credentialId(), keys.familyId(), tokenHash);
            if (sessions.isEmpty() || families.isEmpty() || credentials.isEmpty()) return null;
            var session = sessions.getFirst();
            var credential = credentials.getFirst();
            return new Credential(keys.credentialId(), keys.familyId(), keys.sessionId(),
                credential.expiresAt(), credential.consumedAt(), credential.revokedAt(),
                families.getFirst(), session.revokedAt(), session.inactiveAt(), users.getFirst());
        }

        @Override
        public boolean rotate(UUID credentialId, UUID replacementId, String replacementHash,
                              Instant at, Instant expiresAt) {
            int updated = jdbc.update("""
                UPDATE iam.refresh_credentials SET consumed_at = ?
                 WHERE credential_id = ? AND consumed_at IS NULL AND revoked_at IS NULL
                   AND expires_at > statement_timestamp()
                """, Timestamp.from(at), credentialId);
            if (updated != 1) return false;
            jdbc.update("""
                INSERT INTO iam.refresh_credentials
                  (credential_id, family_id, token_hash, predecessor_id, issued_at, expires_at)
                SELECT ?, family_id, ?, credential_id, ?, ?
                  FROM iam.refresh_credentials WHERE credential_id = ?
                """, replacementId, replacementHash, Timestamp.from(at),
                Timestamp.from(expiresAt), credentialId);
            return true;
        }

        @Override
        public void revokeReusedFamily(UUID familyId, UUID sessionId, UUID userId,
                                       UUID correlationId, Instant at) {
            int updated = jdbc.update("""
                UPDATE iam.refresh_token_families
                   SET reuse_detected_at = ?, revoked_at = ?
                 WHERE family_id = ? AND revoked_at IS NULL
                """, Timestamp.from(at), Timestamp.from(at), familyId);
            if (updated != 1) return;
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "sessionId", sessionId.toString(), "userId", userId.toString(),
                    "reason", "REFRESH_REUSE", "revokedAt", at.toString()));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize SessionRevoked", failure);
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

    private static Instant instant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }

    private record Keys(UUID credentialId, UUID familyId, UUID sessionId, UUID userId) { }
    private record SessionState(Instant revokedAt, Instant inactiveAt) { }
    private record CredentialState(Instant expiresAt, Instant consumedAt,
                                   Instant revokedAt) { }
}
