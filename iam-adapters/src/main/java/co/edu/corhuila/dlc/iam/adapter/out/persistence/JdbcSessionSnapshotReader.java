package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.SessionSnapshotReader;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public final class JdbcSessionSnapshotReader implements SessionSnapshotReader {
    private final JdbcTemplate jdbc;

    public JdbcSessionSnapshotReader(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Snapshot find(UUID userId, UUID sessionId) {
        var rows = jdbc.query("""
            SELECT u.status, u.email_verified_at, u.locked_until,
                   s.revoked_at, s.inactivity_expires_at,
                   ARRAY(SELECT role FROM iam.user_roles r
                         WHERE r.user_id = u.user_id ORDER BY role) AS roles
              FROM iam.sessions s JOIN iam.users u ON u.user_id = s.user_id
             WHERE s.session_id = ? AND u.user_id = ?
            """, (rs, row) -> {
                try {
                    return new Snapshot(rs.getString("status"),
                        instant(rs.getTimestamp("email_verified_at")),
                        instant(rs.getTimestamp("locked_until")),
                        instant(rs.getTimestamp("revoked_at")),
                        instant(rs.getTimestamp("inactivity_expires_at")),
                        List.copyOf(Arrays.asList((String[]) rs.getArray("roles").getArray())));
                } catch (SQLException failure) {
                    throw new IllegalStateException("Cannot read IAM roles", failure);
                }
            }, sessionId, userId);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private static Instant instant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }
}
