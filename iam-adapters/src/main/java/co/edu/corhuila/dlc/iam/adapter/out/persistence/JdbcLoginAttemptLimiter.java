package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.LoginAttemptLimiter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public class JdbcLoginAttemptLimiter implements LoginAttemptLimiter {
    private static final Duration WINDOW = Duration.ofMinutes(5);
    private static final Duration RETENTION = Duration.ofDays(1);
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final byte[] key;

    public JdbcLoginAttemptLimiter(JdbcTemplate jdbc, TransactionTemplate transactions,
                                   @Value("${IAM_IP_DIGEST_KEY_B64}") String keyBase64) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.key = Base64.getDecoder().decode(keyBase64);
        if (key.length < 32) throw new IllegalArgumentException("IP digest key is too short");
    }

    @Override
    public boolean record(String peerIp) {
        byte[] digest = digest(peerIp);
        long lockKey = ByteBuffer.wrap(digest).getLong();
        return Boolean.TRUE.equals(transactions.execute(status -> {
            jdbc.query("SELECT pg_advisory_xact_lock(?)",
                (ResultSetExtractor<Void>) rs -> null, lockKey);
            Timestamp now = jdbc.queryForObject("SELECT clock_timestamp()", Timestamp.class);
            if (now == null) throw new IllegalStateException("Database clock unavailable");
            jdbc.update("DELETE FROM iam.login_ip_attempts WHERE occurred_at < ?",
                Timestamp.from(now.toInstant().minus(RETENTION)));
            Long count = jdbc.queryForObject("""
                SELECT count(*) FROM iam.login_ip_attempts
                 WHERE ip_digest = ? AND occurred_at > ?
                """, Long.class, digest, Timestamp.from(now.toInstant().minus(WINDOW)));
            if (count == null || count >= 10) return false;
            jdbc.update("""
                INSERT INTO iam.login_ip_attempts (attempt_id, ip_digest, occurred_at)
                VALUES (?, ?, ?)
                """, UUID.randomUUID(), digest, now);
            return true;
        }));
    }

    private byte[] digest(String peerIp) {
        if (peerIp == null || !peerIp.matches("(?i)^[0-9a-f:.]+$")
            || (!peerIp.contains(":") && !peerIp.contains("."))) {
            throw new IllegalArgumentException("Invalid network peer address");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(InetAddress.getByName(peerIp).getAddress());
        } catch (UnknownHostException | GeneralSecurityException error) {
            throw new IllegalArgumentException("Invalid network peer address", error);
        }
    }
}
