package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.RoleAssignmentUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcRoleAssignmentUnitOfWork implements RoleAssignmentUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcRoleAssignmentUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
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
        public StaffAccount findForUpdate(UUID userId) {
            var rows = jdbc.query("""
                SELECT user_id,email,display_name,status,version FROM iam.users
                 WHERE user_id = ? FOR UPDATE
                """, (rs, row) -> new StaffAccount(rs.getObject("user_id", UUID.class),
                    rs.getString("email"), rs.getString("display_name"),
                    rs.getString("status"), rs.getLong("version"), roles(userId)), userId);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        private List<String> roles(UUID userId) {
            return jdbc.queryForList(
                "SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role",
                String.class, userId);
        }

        @Override
        public void replaceRoles(UUID userId, List<String> requested, long expectedVersion,
                                 UUID actorId, Instant at) {
            int updated = jdbc.update("""
                UPDATE iam.users SET version = version + 1, updated_at = ?
                 WHERE user_id = ? AND version = ?
                """, Timestamp.from(at), userId, expectedVersion);
            if (updated != 1) throw new ConcurrentModificationException("Staff version changed");
            Set<String> next = Set.copyOf(requested);
            List<String> previous = roles(userId);
            for (String role : previous) {
                if (!next.contains(role)) {
                    jdbc.update("DELETE FROM iam.user_roles WHERE user_id = ? AND role = ?",
                        userId, role);
                }
            }
            for (String role : requested) {
                if (!previous.contains(role)) {
                    jdbc.update("""
                        INSERT INTO iam.user_roles (user_id,role,assigned_by,assigned_at)
                        VALUES (?,?,?,?)
                        """, userId, role, actorId, Timestamp.from(at));
                }
            }
        }

        @Override
        public void appendAudit(UUID userId, String role, String action, UUID actorId,
                                String reason, UUID correlationId, Instant at) {
            jdbc.update("""
                INSERT INTO iam.role_assignment_audit
                  (audit_id,user_id,role,action,actor_user_id,occurred_at,correlation_id,reason)
                VALUES (?,?,?,?,?,?,?,?)
                """, UUID.randomUUID(), userId, role, action, actorId,
                Timestamp.from(at), correlationId, reason);
        }

        @Override
        public void appendRoleEvent(String type, UUID userId, String role, UUID actorId,
                                    UUID correlationId, Instant at) {
            Map<String, String> payload = "RoleAssignedToUser".equals(type)
                ? Map.of("userId", userId.toString(), "role", role,
                    "assignedBy", actorId.toString(), "assignedAt", at.toString())
                : Map.of("userId", userId.toString(), "role", role,
                    "revokedBy", actorId.toString(), "revokedAt", at.toString());
            if (!Set.of("RoleAssignedToUser", "RoleRevokedFromUser").contains(type)) {
                throw new IllegalArgumentException("Unapproved role event");
            }
            appendEvent(type, userId, correlationId, payload, at);
        }

        @Override
        public void revokeSessions(UUID userId, UUID actorId, UUID correlationId, Instant at) {
            var sessions = jdbc.query("""
                SELECT session_id FROM iam.sessions
                 WHERE user_id = ? AND revoked_at IS NULL
                 ORDER BY session_id FOR UPDATE
                """, (rs, row) -> rs.getObject(1, UUID.class), userId);
            for (UUID sessionId : sessions) {
                jdbc.update("""
                    UPDATE iam.sessions SET revoked_at = ?,
                        revocation_reason = 'ROLE_ASSIGNMENTS_CHANGED'
                     WHERE session_id = ? AND revoked_at IS NULL
                    """, Timestamp.from(at), sessionId);
                appendEvent("SessionRevoked", sessionId, correlationId, Map.of(
                    "sessionId", sessionId.toString(), "userId", userId.toString(),
                    "reason", "ROLE_ASSIGNMENTS_CHANGED", "revokedAt", at.toString()), at);
            }
        }

        private void appendEvent(String type, UUID aggregateId, UUID correlationId,
                                 Map<String, String> payload, Instant at) {
            try {
                jdbc.update("""
                    INSERT INTO iam.outbox_events
                      (event_id,event_type,aggregate_id,correlation_id,causation_id,payload,occurred_at)
                    VALUES (?,?,?,?,?,?::jsonb,?)
                    """, UUID.randomUUID(), type, aggregateId, correlationId, correlationId,
                    json.writeValueAsString(payload), Timestamp.from(at));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize approved event", failure);
            }
        }
    }
}
