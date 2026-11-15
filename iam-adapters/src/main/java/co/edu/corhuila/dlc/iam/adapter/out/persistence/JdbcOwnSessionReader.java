package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionReader;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public class JdbcOwnSessionReader implements OwnSessionReader {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate snapshot;

    public JdbcOwnSessionReader(JdbcTemplate jdbc, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.snapshot = new TransactionTemplate(transactions);
        snapshot.setReadOnly(true);
        snapshot.setIsolationLevel(TransactionTemplate.ISOLATION_REPEATABLE_READ);
    }

    @Override
    public Page read(UUID ownerId, int limit, long offset) {
        return snapshot.execute(status -> {
            Long total = jdbc.queryForObject(
                "SELECT count(*) FROM iam.sessions WHERE user_id = ?", Long.class, ownerId);
            var rows = jdbc.query("""
                SELECT session_id, device_id, created_at, last_user_activity_at,
                       inactivity_expires_at, version
                  FROM iam.sessions
                 WHERE user_id = ?
                 ORDER BY created_at ASC, session_id ASC
                 LIMIT ? OFFSET ?
                """, (rs, index) -> new Session(
                    rs.getObject("session_id", UUID.class), rs.getString("device_id"),
                    rs.getTimestamp("created_at").toInstant(),
                    rs.getTimestamp("last_user_activity_at").toInstant(),
                    rs.getTimestamp("inactivity_expires_at").toInstant(),
                    rs.getLong("version")), ownerId, limit, offset);
            return new Page(total, rows);
        });
    }
}
