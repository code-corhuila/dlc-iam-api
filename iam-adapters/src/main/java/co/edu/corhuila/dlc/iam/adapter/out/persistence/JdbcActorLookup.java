package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.ActorLookup;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class JdbcActorLookup implements ActorLookup {
    private final JdbcTemplate jdbc;

    public JdbcActorLookup(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public List<String> activeRoles(UUID userId, UUID sessionId, Instant now) {
        return jdbc.queryForList("""
            SELECT r.role FROM iam.sessions s
              JOIN iam.users u ON u.user_id = s.user_id
              JOIN iam.user_roles r ON r.user_id = u.user_id
             WHERE s.session_id = ? AND s.user_id = ?
               AND s.revoked_at IS NULL AND s.inactivity_expires_at > ?
               AND u.status = 'ACTIVE' AND u.email_verified_at IS NOT NULL
             ORDER BY r.role
            """, String.class, sessionId, userId, Timestamp.from(now));
    }
}
