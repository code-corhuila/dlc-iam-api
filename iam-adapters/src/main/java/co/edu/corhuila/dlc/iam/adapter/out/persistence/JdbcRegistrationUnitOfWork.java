package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.RegistrationUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcRegistrationUnitOfWork implements RegistrationUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public JdbcRegistrationUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions,
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
                SELECT actor_user_id,user_id,request_proof,normalized_email,display_name,
                       initial_role,initial_status,created_at,initial_version
                  FROM iam.registration_requests WHERE idempotency_key = ?
                """, (rs, row) -> new Attempt(rs.getObject(1, UUID.class), rs.getBytes(3),
                    new Staff(rs.getObject(2, UUID.class), rs.getString(4), rs.getString(5),
                        rs.getString(6), rs.getString(7), rs.getTimestamp(8).toInstant(),
                        rs.getLong(9))), key);
            return rows.isEmpty() ? null : rows.getFirst();
        }

        @Override
        public boolean emailExists(String normalizedEmail) {
            return !jdbc.query("SELECT user_id FROM iam.users WHERE email = ?",
                (rs, row) -> rs.getObject(1, UUID.class), normalizedEmail).isEmpty();
        }

        @Override
        public void createStaff(UUID userId, UUID actorId, String normalizedEmail,
                                String passwordHash, String name, String role, Instant at) {
            jdbc.update("""
                INSERT INTO iam.users
                  (user_id,email,password_hash,display_name,status,created_at,updated_at,version)
                VALUES (?,?,?,?,'PENDING_VERIFICATION',?,?,1)
                """, userId, normalizedEmail, passwordHash, name, Timestamp.from(at),
                Timestamp.from(at));
            jdbc.update("""
                INSERT INTO iam.user_roles (user_id,role,assigned_by,assigned_at)
                VALUES (?,?,?,?)
                """, userId, role, actorId, Timestamp.from(at));
        }

        @Override
        public void appendAudit(UUID userId, UUID actorId, UUID correlationId, Instant at) {
            jdbc.update("""
                INSERT INTO iam.staff_account_audit
                  (audit_id,user_id,action,actor_user_id,prior_status,next_status,
                   occurred_at,correlation_id)
                VALUES (?,?,'REGISTERED',?,NULL,'PENDING_VERIFICATION',?,?)
                """, UUID.randomUUID(), userId, actorId, Timestamp.from(at), correlationId);
        }

        @Override
        public void appendUserRegistered(UUID userId, UUID actorId, UUID correlationId,
                                         Instant at) {
            var details = jdbc.queryForMap("""
                SELECT u.email,r.role FROM iam.users u JOIN iam.user_roles r ON r.user_id=u.user_id
                 WHERE u.user_id=?
                """, userId);
            String email = (String) details.get("email");
            String role = (String) details.get("role");
            String payload;
            try {
                payload = json.writeValueAsString(Map.of(
                    "userId", userId.toString(), "emailHash", hashEmail(email),
                    "initialRoles", List.of(role), "status", "PENDING_VERIFICATION"));
            } catch (JsonProcessingException failure) {
                throw new IllegalStateException("Cannot serialize approved event", failure);
            }
            jdbc.update("""
                INSERT INTO iam.outbox_events
                  (event_id,event_type,aggregate_id,correlation_id,causation_id,payload,occurred_at)
                VALUES (?,'UserRegistered',?,?,?,?::jsonb,?)
                """, UUID.randomUUID(), userId, correlationId, correlationId,
                payload, Timestamp.from(at));
        }

        @Override
        public void rememberAttempt(UUID key, UUID actorId, byte[] proof, Staff staff) {
            jdbc.update("""
                INSERT INTO iam.registration_requests
                  (idempotency_key,actor_user_id,user_id,request_proof,normalized_email,
                   display_name,initial_role,initial_status,initial_version,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """, key, actorId, staff.id(), proof, staff.email(), staff.name(), staff.role(),
                staff.status(), staff.version(), Timestamp.from(staff.createdAt()));
        }
    }

    private static String hashEmail(String normalizedEmail) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(normalizedEmail.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 unavailable", failure);
        }
    }
}
