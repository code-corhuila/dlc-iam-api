package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import co.edu.corhuila.dlc.iam.adapter.out.events.IamEventEnvelope;
import co.edu.corhuila.dlc.iam.adapter.out.events.RabbitOutboxPublisher;
import co.edu.corhuila.dlc.iam.application.port.out.OutboxPublisher;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

class RabbitOutboxPublisherTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final IamEventEnvelope envelope = new IamEventEnvelope(mapper);

    private OutboxPublisher.Event event(String type) {
        return new OutboxPublisher.Event(UUID.randomUUID(), type, UUID.randomUUID(),
            UUID.randomUUID(), UUID.randomUUID(), "{\"userId\":\"" + UUID.randomUUID() + "\"}",
            Instant.parse("2026-11-05T12:00:00Z"));
    }

    @Test
    void envelopeMatchesApprovedMetadataAndRejectsUnknownTypes() throws Exception {
        var user = event("UserRegistered");
        var json = mapper.readTree(envelope.serialize(user));
        assertEquals(user.id().toString(), json.get("eventId").asText());
        assertEquals("User", json.get("aggregateType").asText());
        assertEquals("auth-service", json.get("producer").asText());
        assertEquals(1, json.get("version").asInt());
        assertEquals(user.correlationId().toString(), json.get("metadata").get("correlationId").asText());
        assertEquals(user.causationId().toString(), json.get("metadata").get("causationId").asText());
        assertTrue(json.get("metadata").get("actorUserId").isNull());
        assertEquals("Session", mapper.readTree(envelope.serialize(event("SessionStarted")))
            .get("aggregateType").asText());
        assertThrows(IllegalArgumentException.class, () -> envelope.serialize(event("UnapprovedEvent")));
    }

    @Test
    void onlyBrokerAckCountsAsPublished() {
        RabbitTemplate rabbit = mock(RabbitTemplate.class);
        var publisher = new RabbitOutboxPublisher(rabbit, envelope, "iam.events.v1");
        var event = event("UserLocked");
        doAnswer(call -> {
            Message message = call.getArgument(2);
            CorrelationData confirmation = call.getArgument(3);
            assertEquals(event.id().toString(), message.getMessageProperties().getMessageId());
            assertEquals("application/json", message.getMessageProperties().getContentType());
            confirmation.getFuture().complete(new CorrelationData.Confirm(true, null));
            return null;
        }).when(rabbit).send(eq("iam.events.v1"), eq("iam.UserLocked.v1"), any(Message.class),
            any(CorrelationData.class));
        assertDoesNotThrow(() -> publisher.publish(event));
        verify(rabbit).send(eq("iam.events.v1"), eq("iam.UserLocked.v1"), any(Message.class),
            any(CorrelationData.class));

        reset(rabbit);
        doAnswer(call -> {
            CorrelationData confirmation = call.getArgument(3);
            confirmation.getFuture().complete(new CorrelationData.Confirm(false, "rejected"));
            return null;
        }).when(rabbit).send(anyString(), anyString(), any(Message.class), any(CorrelationData.class));
        assertThrows(IllegalStateException.class, () -> publisher.publish(event));
    }
}
