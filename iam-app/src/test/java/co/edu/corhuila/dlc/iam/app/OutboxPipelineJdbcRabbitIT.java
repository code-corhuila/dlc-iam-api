package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import co.edu.corhuila.dlc.iam.adapter.out.events.IamEventEnvelope;
import co.edu.corhuila.dlc.iam.adapter.out.events.RabbitOutboxPublisher;
import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcOutboxDelivery;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

class OutboxPipelineJdbcRabbitIT {
    @Test
    void onlyRoutedBrokerConfirmationMarksOwnerRowPublished() throws Exception {
        String jdbcUrl = System.getenv("IAM_TEST_JDBC_URL");
        String rabbitHost = System.getenv("IAM_TEST_RABBIT_HOST");
        assumeTrue(jdbcUrl != null && rabbitHost != null);
        var source = new DriverManagerDataSource(jdbcUrl, "iam_runtime", "");
        var jdbc = new JdbcTemplate(source);
        var delivery = new JdbcOutboxDelivery(jdbc,
            new TransactionTemplate(new DataSourceTransactionManager(source)));
        var connection = new CachingConnectionFactory(rabbitHost);
        connection.setUsername(System.getenv("IAM_TEST_RABBIT_USER"));
        connection.setPassword(System.getenv("IAM_TEST_RABBIT_PASSWORD"));
        connection.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
        connection.setPublisherReturns(true);
        try {
            var rabbit = new RabbitTemplate(connection);
            rabbit.setMandatory(true);
            var admin = new RabbitAdmin(connection);
            var exchange = new TopicExchange("iam.events.v1", true, false);
            var queue = new Queue("iam-outbox-pipeline-test", false, false, true);
            admin.declareExchange(exchange);
            admin.declareQueue(queue);
            admin.declareBinding(BindingBuilder.bind(queue).to(exchange).with("iam.UserLocked.v1"));
            var publisher = new RabbitOutboxPublisher(rabbit,
                new IamEventEnvelope(new ObjectMapper()), exchange.getName());

            UUID delivered = insert(jdbc, "UserLocked");
            assertTrue(delivery.deliverNext(publisher));
            assertNotNull(jdbc.queryForObject(
                "SELECT published_at FROM iam.outbox_events WHERE event_id=?",
                Timestamp.class, delivered));
            var received = rabbit.receive(queue.getName(), 3000);
            assertNotNull(received);
            assertEquals(delivered.toString(), new ObjectMapper().readTree(received.getBody())
                .get("eventId").asText());

            UUID unroutable = insert(jdbc, "UserUnlocked");
            assertTrue(delivery.deliverNext(publisher));
            assertNull(jdbc.queryForObject(
                "SELECT published_at FROM iam.outbox_events WHERE event_id=?",
                Timestamp.class, unroutable));
            assertEquals(1, jdbc.queryForObject(
                "SELECT delivery_attempts FROM iam.outbox_events WHERE event_id=?",
                Integer.class, unroutable));
            admin.deleteQueue(queue.getName());
        } finally {
            connection.destroy();
        }
    }

    private UUID insert(JdbcTemplate jdbc, String type) {
        UUID id = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID correlation = UUID.randomUUID();
        String payload = type.equals("UserLocked")
            ? "{\"userId\":\"" + user + "\",\"lockedUntil\":\"2026-11-05T23:00:00Z\",\"reason\":\"FAILED_ATTEMPTS\"}"
            : "{\"userId\":\"" + user + "\",\"unlockedAt\":\"2026-11-05T22:00:00Z\",\"mode\":\"EXPIRY\"}";
        jdbc.update("""
            INSERT INTO iam.outbox_events
              (event_id,event_type,aggregate_id,correlation_id,causation_id,payload,occurred_at)
            VALUES (?,?,?,?,?,?::jsonb,statement_timestamp())
            """, id, type, user, correlation, correlation, payload);
        return id;
    }
}
