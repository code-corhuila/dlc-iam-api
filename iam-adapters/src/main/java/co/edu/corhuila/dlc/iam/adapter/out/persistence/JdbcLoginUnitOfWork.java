package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public class JdbcLoginUnitOfWork implements LoginUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcLoginUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
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
        public StaffAccount findForUpdate(String email) {
            var found = jdbc.query("""
                SELECT user_id, email, display_name, password_hash, status,
                       email_verified_at, failed_attempts, locked_until, version
                  FROM iam.users WHERE email = ? FOR UPDATE
                """, (rs, row) -> new StaffAccount(
                    rs.getObject("user_id", UUID.class), rs.getString("email"),
                    rs.getString("display_name"), rs.getString("password_hash"),
                    rs.getString("status"), instantOrNull(rs.getTimestamp("email_verified_at")),
                    rs.getInt("failed_attempts"), instantOrNull(rs.getTimestamp("locked_until")),
                    rs.getLong("version"), roles(rs.getObject("user_id", UUID.class))), email);
            return found.isEmpty() ? null : found.getFirst();
        }

        private List<String> roles(UUID userId) {
            return jdbc.queryForList(
                "SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role",
                String.class, userId);
        }

        @Override
        public void recordFailedPassword(StaffAccount staff, Instant at, UUID correlationId) {
            int failures = staff.failedAttempts() + 1;
            boolean locked = failures >= 3;
            Instant until = locked ? at.plus(Duration.ofMinutes(15)) : null;
            jdbc.update("""
                UPDATE iam.users SET failed_attempts = ?, status = ?, locked_until = ?,
                                     updated_at = ?, version = version + 1 WHERE user_id = ?
                """, failures, locked ? "LOCKED" : "ACTIVE", timestampOrNull(until),
                Timestamp.from(at), staff.id());
            if (locked) {
                jdbc.update("""
                    INSERT INTO iam.account_lock_audit
                      (audit_id, user_id, action, failed_attempts, locked_until,
                       occurred_at, correlation_id)
                    VALUES (?, ?, 'LOCKED', 3, ?, ?, ?)
                    """, UUID.randomUUID(), staff.id(), Timestamp.from(until),
                    Timestamp.from(at), correlationId);
                appendSecurityEvent("UserLocked", staff.id(), correlationId,
                    Map.of("userId", staff.id().toString(), "lockedUntil", until.toString(),
                           "reason", "FAILED_ATTEMPTS"), at);
            }
        }

        @Override
        public StaffAccount unlockExpired(StaffAccount staff, Instant at, UUID correlationId) {
            jdbc.update("""
                UPDATE iam.users SET status = 'ACTIVE', failed_attempts = 0,
                                     locked_until = NULL, updated_at = ?,
                                     version = version + 1 WHERE user_id = ?
                """, Timestamp.from(at), staff.id());
            jdbc.update("""
                INSERT INTO iam.account_lock_audit
                  (audit_id, user_id, action, failed_attempts, occurred_at,
                   correlation_id, unlock_source)
                VALUES (?, ?, 'UNLOCKED', 0, ?, ?, 'EXPIRY')
                """, UUID.randomUUID(), staff.id(), Timestamp.from(at), correlationId);
            appendSecurityEvent("UserUnlocked", staff.id(), correlationId,
                Map.of("userId", staff.id().toString(), "unlockedAt", at.toString(),
                       "mode", "EXPIRY"), at);
            return new StaffAccount(staff.id(), staff.email(), staff.name(),
                staff.passwordHash(), "ACTIVE", staff.verifiedAt(), 0, null,
                staff.version() + 1, staff.roles());
        }

        private void appendSecurityEvent(String type, UUID userId, UUID correlationId,
                                         Map<String, String> payload, Instant at) {
            try {
                jdbc.update("""
                    INSERT INTO iam.outbox_events
                      (event_id, event_type, aggregate_id, correlation_id,
                       causation_id, payload, occurred_at)
                    VALUES (?, ?, ?, ?, ?, ?::jsonb, ?)
                    """, UUID.randomUUID(), type, userId, correlationId, correlationId,
                    json.writeValueAsString(payload), Timestamp.from(at));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize owner event", failure);
            }
        }

        @Override
        public void resetFailures(UUID userId, Instant at) {
            jdbc.update("""
                UPDATE iam.users SET failed_attempts = 0, updated_at = ?,
                                     version = version + 1 WHERE user_id = ?
                """, Timestamp.from(at), userId);
        }

        @Override
        public void createSession(UUID sessionId, UUID userId, String deviceId,
                                  Instant at, Instant inactiveAt) {
            jdbc.update("""
                INSERT INTO iam.sessions
                  (session_id, user_id, device_id, created_at,
                   last_user_activity_at, inactivity_expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, sessionId, userId, deviceId, Timestamp.from(at),
                Timestamp.from(at), Timestamp.from(inactiveAt));
        }

        @Override
        public void createRefresh(UUID familyId, UUID sessionId, UUID credentialId,
                                  String tokenHash, Instant at, Instant expiresAt) {
            jdbc.update("""
                INSERT INTO iam.refresh_token_families (family_id, session_id, created_at)
                VALUES (?, ?, ?)
                """, familyId, sessionId, Timestamp.from(at));
            jdbc.update("""
                INSERT INTO iam.refresh_credentials
                  (credential_id, family_id, token_hash, issued_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """, credentialId, familyId, tokenHash, Timestamp.from(at),
                Timestamp.from(expiresAt));
        }

        @Override
        public void appendSessionStarted(UUID eventId, UUID correlationId,
                                         UUID sessionId, UUID userId, String deviceId,
                                         Instant at, Instant expiresAt) {
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "sessionId", sessionId.toString(),
                    "userId", userId.toString(),
                    "deviceId", deviceId,
                    "startedAt", at.toString(),
                    "expiresAt", expiresAt.toString()));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize owner event", failure);
            }
            jdbc.update("""
                INSERT INTO iam.outbox_events
                  (event_id, event_type, aggregate_id, correlation_id,
                   causation_id, payload, occurred_at)
                VALUES (?, 'SessionStarted', ?, ?, ?, ?::jsonb, ?)
                """, eventId, sessionId, correlationId, correlationId, payload,
                Timestamp.from(at));
        }
    }

    private static Instant instantOrNull(Timestamp value) {
        return value == null ? null : value.toInstant();
    }

    private static Timestamp timestampOrNull(Instant value) {
        return value == null ? null : Timestamp.from(value);
    }
}
