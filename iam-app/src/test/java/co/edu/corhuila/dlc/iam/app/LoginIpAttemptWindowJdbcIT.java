package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcLoginIpAttemptWindow;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Run against a disposable IAM database with login IP migration 009 as iam_runtime. */
@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class LoginIpAttemptWindowJdbcIT {
    @Test
    void concurrentAttemptsAllowExactlyTenAndExpireByWindow() throws Exception {
        var source = new DriverManagerDataSource(System.getenv("IAM_TEST_JDBC_URL"),
            "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var store = new JdbcLoginIpAttemptWindow(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source)));
        byte[] digest = new byte[32];
        new SecureRandom().nextBytes(digest);
        Instant at = Instant.now();
        var start = new CountDownLatch(1);
        var pool = Executors.newFixedThreadPool(12);
        try {
            var results = new ArrayList<Future<Boolean>>();
            for (int index = 0; index < 12; index++) {
                results.add(pool.submit(() -> {
                    start.await();
                    return store.recordIfBelowLimit(digest, at.minusSeconds(300), at, 10);
                }));
            }
            start.countDown();
            int allowed = 0;
            for (var result : results) if (result.get(15, TimeUnit.SECONDS)) allowed++;
            assertEquals(10, allowed);
        } finally {
            pool.shutdownNow();
        }
        Integer count = jdbc.queryForObject("""
            SELECT count(*) FROM iam.login_ip_attempts WHERE ip_digest = ?
            """, Integer.class, digest);
        assertEquals(10, count);
        assertFalse(store.recordIfBelowLimit(digest, at.minusSeconds(300), at, 10));
        assertTrue(store.recordIfBelowLimit(digest, at.plusSeconds(60),
            at.plusSeconds(360), 10));
        assertEquals(1, jdbc.queryForObject("""
            SELECT count(*) FROM iam.login_ip_attempts
             WHERE ip_digest = ? AND occurred_at > ?
            """, Integer.class, digest, Timestamp.from(at.plusSeconds(60))));
    }
}
