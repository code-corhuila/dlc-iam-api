package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcOutboxDelivery;
import java.sql.Timestamp;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

@EnabledIfEnvironmentVariable(named = "IAM_TEST_JDBC_URL", matches = ".+")
class OutboxDeliveryJdbcIT {
    private final DriverManagerDataSource source = new DriverManagerDataSource(
        System.getenv("IAM_TEST_JDBC_URL"), "iam_runtime", "");
    private final JdbcTemplate jdbc = new JdbcTemplate(source);
    private final JdbcOutboxDelivery delivery = new JdbcOutboxDelivery(jdbc,
        new TransactionTemplate(new DataSourceTransactionManager(source)));

    @Test
    void confirmsOnceAndDoesNotRepublishMarkedEvent() {
        UUID id = insertEvent();
        AtomicInteger calls = new AtomicInteger();
        assertTrue(delivery.deliverNext(event -> {
            assertEquals(id, event.id());
            assertEquals("UserLocked", event.type());
            assertTrue(event.payloadJson().contains("userId"));
            calls.incrementAndGet();
        }));
        assertNotNull(jdbc.queryForObject(
            "SELECT published_at FROM iam.outbox_events WHERE event_id=?", Timestamp.class, id));
        assertFalse(delivery.deliverNext(event -> calls.incrementAndGet()));
        assertEquals(1, calls.get());
    }

    @Test
    void brokerFailureBacksOffThenRequiresReconciliationAfterTenAttempts() {
        UUID id = insertEvent();
        for (int attempt = 1; attempt <= 10; attempt++) {
            assertTrue(delivery.deliverNext(event -> { throw new IllegalStateException("broker down"); }));
            assertEquals(attempt, jdbc.queryForObject(
                "SELECT delivery_attempts FROM iam.outbox_events WHERE event_id=?",
                Integer.class, id));
            assertNull(jdbc.queryForObject(
                "SELECT published_at FROM iam.outbox_events WHERE event_id=?", Timestamp.class, id));
            if (attempt < 10) jdbc.update("""
                UPDATE iam.outbox_events SET next_delivery_at=statement_timestamp()-interval '1 second'
                 WHERE event_id=?
                """, id);
        }
        assertNotNull(jdbc.queryForObject(
            "SELECT reconciliation_required_at FROM iam.outbox_events WHERE event_id=?",
            Timestamp.class, id));
        assertFalse(delivery.deliverNext(event -> { throw new AssertionError("exhausted event delivered"); }));
    }

    @Test
    void secondDispatcherSkipsLockedEvent() throws Exception {
        insertEvent();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var first = pool.submit(() -> delivery.deliverNext(event -> {
                entered.countDown();
                try {
                    if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("timeout");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(interrupted);
                }
            }));
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            var second = pool.submit(() -> delivery.deliverNext(event -> {
                throw new AssertionError("same event claimed twice");
            }));
            assertFalse(second.get(5, TimeUnit.SECONDS));
            release.countDown();
            assertTrue(first.get(5, TimeUnit.SECONDS));
        }
    }

    private UUID insertEvent() {
        UUID id = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID correlation = UUID.randomUUID();
        jdbc.update("""
            INSERT INTO iam.outbox_events
              (event_id,event_type,aggregate_id,correlation_id,causation_id,payload,occurred_at)
            VALUES (?,'UserLocked',?,?,?,?::jsonb,statement_timestamp())
            """, id, user, correlation, correlation,
            "{\"userId\":\"" + user + "\"}");
        return id;
    }
}
