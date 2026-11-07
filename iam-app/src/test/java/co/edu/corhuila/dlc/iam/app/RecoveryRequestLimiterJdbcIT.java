package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcRecoveryRequestLimiter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.Executors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Requires an isolated IAM database with the identity-email limiter migration. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class RecoveryRequestLimiterJdbcIT {
    private static final byte[] KEY = new byte[32];
    private final DriverManagerDataSource source = new DriverManagerDataSource(
        System.getenv("IAM_TEST_JDBC_URL"), "iam_runtime", "");
    private final JdbcTemplate jdbc = new JdbcTemplate(source);
    private final JdbcRecoveryRequestLimiter limiter = new JdbcRecoveryRequestLimiter(jdbc,
        new TransactionTemplate(new DataSourceTransactionManager(source)),
        Base64.getEncoder().encodeToString(KEY));

    @Test
    void emailCooldownAndHourlyQuotaApplyWithoutStoringRawIdentity() throws Exception {
        String ip = "ip-" + UUID.randomUUID();
        String email = UUID.randomUUID() + "@example.test";
        assertTrue(limiter.allow(ip, email));
        assertFalse(limiter.allow(ip, email));
        for (int allowed = 2; allowed <= 3; allowed++) {
            jdbc.update("""
                UPDATE iam.identity_email_limits
                   SET window_started_at=statement_timestamp()-interval '2 minutes',
                       last_allowed_at=statement_timestamp()-interval '61 seconds'
                 WHERE purpose='PASSWORD_RECOVERY' AND key_kind='NORMALIZED_EMAIL'
                   AND key_digest=?
                """, digest("NORMALIZED_EMAIL", email));
            assertTrue(limiter.allow(ip, email));
        }
        assertFalse(limiter.allow(ip, email));
        assertEquals(3, jdbc.queryForObject("""
            SELECT attempt_count FROM iam.identity_email_limits
             WHERE purpose='PASSWORD_RECOVERY' AND key_kind='NORMALIZED_EMAIL'
               AND key_digest=?
            """, Integer.class, digest("NORMALIZED_EMAIL", email)));
    }

    @Test
    void concurrentRequestsAcrossConnectionsCannotExceedIpQuota() throws Exception {
        String ip = "ip-" + UUID.randomUUID();
        try (var pool = Executors.newFixedThreadPool(12)) {
            var futures = new ArrayList<java.util.concurrent.Future<Boolean>>();
            for (int i = 0; i < 12; i++) {
                futures.add(pool.submit(() -> limiter.allow(ip,
                    UUID.randomUUID() + "@example.test")));
            }
            int accepted = 0;
            for (var future : futures) if (future.get()) accepted++;
            assertEquals(10, accepted);
        }
        assertEquals(10, jdbc.queryForObject("""
            SELECT attempt_count FROM iam.identity_email_limits
             WHERE purpose='PASSWORD_RECOVERY' AND key_kind='SOURCE_IP'
               AND key_digest=?
            """, Integer.class, digest("SOURCE_IP", ip)));
    }

    private static byte[] digest(String kind, String value) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
        return mac.doFinal((kind + ":" + value).getBytes(StandardCharsets.UTF_8));
    }
}
