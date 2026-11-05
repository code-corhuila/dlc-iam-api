package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.RecoveryRequestLimiter;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationRequestLimiter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/** Atomic, owner-scoped rate limits shared by all Auth instances. */
@Repository
public final class JdbcRecoveryRequestLimiter implements RecoveryRequestLimiter, VerificationRequestLimiter {
    private static final Duration IP_WINDOW = Duration.ofMinutes(5);
    private static final Duration EMAIL_WINDOW = Duration.ofHours(1);
    private static final Duration EMAIL_COOLDOWN = Duration.ofSeconds(60);
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final byte[] key;

    public JdbcRecoveryRequestLimiter(JdbcTemplate jdbc, TransactionTemplate transactions,
            @Value("${IAM_IDENTITY_EMAIL_LIMIT_KEY_BASE64}") String encodedKey) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.key = Base64.getDecoder().decode(encodedKey);
        if (key.length < 32) {
            throw new IllegalArgumentException("IAM identity email limit key must contain 256 bits");
        }
    }

    @Override
    public boolean allow(String requesterKey, String normalizedEmail) {
        return allowFor("PASSWORD_RECOVERY", requesterKey, normalizedEmail);
    }

    @Override
    public boolean allowVerification(String requesterKey, String normalizedEmail) {
        return allowFor("EMAIL_VERIFICATION", requesterKey, normalizedEmail);
    }

    private boolean allowFor(String purpose, String requesterKey, String normalizedEmail) {
        if (requesterKey == null || requesterKey.isBlank()
            || normalizedEmail == null || normalizedEmail.isBlank()) {
            throw new IllegalArgumentException("Invalid identity email limit key");
        }
        byte[] ip = digest("SOURCE_IP", requesterKey);
        byte[] email = digest("NORMALIZED_EMAIL", normalizedEmail);
        Boolean allowed = transactions.execute(status -> {
            if (!take(purpose, "SOURCE_IP", ip, IP_WINDOW, Duration.ZERO, 10)) return false;
            return take(purpose, "NORMALIZED_EMAIL", email, EMAIL_WINDOW, EMAIL_COOLDOWN, 3);
        });
        return Boolean.TRUE.equals(allowed);
    }

    private boolean take(String purpose, String kind, byte[] digest,
                         Duration window, Duration cooldown, int max) {
        int inserted = jdbc.update("""
            INSERT INTO iam.identity_email_limits
              (purpose,key_kind,key_digest,window_started_at,last_allowed_at,attempt_count)
            VALUES (?,?,?,statement_timestamp(),statement_timestamp(),1)
            ON CONFLICT DO NOTHING
            """, purpose, kind, digest);
        if (inserted == 1) return true;
        Limit previous = jdbc.queryForObject("""
            SELECT window_started_at,last_allowed_at,attempt_count
              FROM iam.identity_email_limits
             WHERE purpose=? AND key_kind=? AND key_digest=? FOR UPDATE
            """, (rs, row) -> new Limit(
                rs.getTimestamp(1).toInstant(), rs.getTimestamp(2).toInstant(), rs.getInt(3)),
            purpose, kind, digest);
        Instant now = jdbc.queryForObject("SELECT statement_timestamp()", Timestamp.class).toInstant();
        if (previous.windowStarted().plus(window).isAfter(now)) {
            if (previous.attempts() >= max || previous.lastAllowed().plus(cooldown).isAfter(now)) {
                return false;
            }
            jdbc.update("""
                UPDATE iam.identity_email_limits
                   SET last_allowed_at=?,attempt_count=attempt_count+1
                 WHERE purpose=? AND key_kind=? AND key_digest=?
                """, Timestamp.from(now), purpose, kind, digest);
        } else {
            jdbc.update("""
                UPDATE iam.identity_email_limits
                   SET window_started_at=?,last_allowed_at=?,attempt_count=1
                 WHERE purpose=? AND key_kind=? AND key_digest=?
                """, Timestamp.from(now), Timestamp.from(now), purpose, kind, digest);
        }
        return true;
    }

    private byte[] digest(String kind, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal((kind + ":" + value).getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("IAM limit digest unavailable", failure);
        }
    }

    private record Limit(Instant windowStarted, Instant lastAllowed, int attempts) { }
}
