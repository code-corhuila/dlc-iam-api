package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.LoginIpAttemptWindow;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcLoginIpAttemptWindow implements LoginIpAttemptWindow {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public JdbcLoginIpAttemptWindow(JdbcTemplate jdbc, TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public boolean recordIfBelowLimit(byte[] ipDigest, Instant after, Instant at, int limit) {
        if (ipDigest == null || ipDigest.length != 32 || after == null || at == null || limit < 1) {
            throw new IllegalArgumentException("Invalid login attempt window");
        }
        return transactions.execute(status -> {
            // A collision only serializes unrelated IPs; each count still uses the full digest.
            long lockKey = ByteBuffer.wrap(ipDigest).getLong();
            jdbc.query("SELECT pg_advisory_xact_lock(?)", rs -> null, lockKey);
            Integer count = jdbc.queryForObject("""
                SELECT count(*) FROM iam.login_ip_attempts
                 WHERE ip_digest = ? AND occurred_at > ?
                """, Integer.class, ipDigest, Timestamp.from(after));
            if (count >= limit) return false;
            jdbc.update("""
                INSERT INTO iam.login_ip_attempts (attempt_id, ip_digest, occurred_at)
                VALUES (?, ?, ?)
                """, UUID.randomUUID(), ipDigest, Timestamp.from(at));
            return true;
        });
    }
}
