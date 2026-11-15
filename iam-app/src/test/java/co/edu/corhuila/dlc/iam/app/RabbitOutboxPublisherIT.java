package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import co.edu.corhuila.dlc.iam.adapter.out.events.IamEventEnvelope;
import co.edu.corhuila.dlc.iam.adapter.out.events.RabbitOutboxPublisher;
import co.edu.corhuila.dlc.iam.application.port.out.OutboxPublisher;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

class RabbitOutboxPublisherIT {
    @Test
    void routedEventIsConfirmedAndUnroutableEventIsRejected() throws Exception {
        String host = System.getenv("IAM_TEST_RABBIT_HOST");
        assumeTrue(host != null && !host.isBlank());
        var connection = new CachingConnectionFactory(host);
        connection.setUsername(System.getenv().getOrDefault("IAM_TEST_RABBIT_USER", "guest"));
        connection.setPassword(System.getenv().getOrDefault("IAM_TEST_RABBIT_PASSWORD", "guest"));
        connection.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
        connection.setPublisherReturns(true);
        try {
            var rabbit = new RabbitTemplate(connection);
            rabbit.setMandatory(true);
            var admin = new RabbitAdmin(connection);
            var exchange = new TopicExchange("iam.events.v1", true, false);
            var queue = new Queue("iam-outbox-publisher-test", false, false, true);
            admin.declareExchange(exchange);
            admin.declareQueue(queue);
            admin.declareBinding(BindingBuilder.bind(queue).to(exchange).with("iam.UserLocked.v1"));
            var publisher = new RabbitOutboxPublisher(rabbit,
                new IamEventEnvelope(new ObjectMapper()), exchange.getName());
            var event = event("UserLocked");
            publisher.publish(event);
            var received = rabbit.receive(queue.getName(), 3000);
            assertNotNull(received);
            assertEquals(event.id().toString(), received.getMessageProperties().getMessageId());
            assertEquals(event.id().toString(), new ObjectMapper().readTree(received.getBody())
                .get("eventId").asText());
            assertThrows(IllegalStateException.class, () -> publisher.publish(event("UserUnlocked")));
            admin.deleteQueue(queue.getName());
        } finally {
            connection.destroy();
        }
    }

    private OutboxPublisher.Event event(String type) {
        return new OutboxPublisher.Event(UUID.randomUUID(), type, UUID.randomUUID(),
            UUID.randomUUID(), UUID.randomUUID(), "{}", Instant.now());
    }
}
