package co.edu.corhuila.dlc.iam.adapter.out.events;

import co.edu.corhuila.dlc.iam.application.port.out.OutboxPublisher;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Set;
import org.springframework.stereotype.Component;

/** Serializes the approved auth event envelope without exposing transport details to core. */
@Component
public final class IamEventEnvelope {
    private static final Set<String> USER_EVENTS = Set.of("UserRegistered", "UserEmailVerified",
        "UserLocked", "UserUnlocked", "RoleAssignedToUser", "RoleRevokedFromUser");
    private static final Set<String> SESSION_EVENTS = Set.of("SessionStarted", "SessionRevoked");
    private final ObjectMapper mapper;

    public IamEventEnvelope(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public byte[] serialize(OutboxPublisher.Event event) {
        String aggregateType;
        if (USER_EVENTS.contains(event.type())) aggregateType = "User";
        else if (SESSION_EVENTS.contains(event.type())) aggregateType = "Session";
        else throw new IllegalArgumentException("Unsupported IAM event type");
        try {
            var payload = mapper.readTree(event.payloadJson());
            if (!payload.isObject()) throw new IllegalArgumentException("IAM event payload must be an object");
            ObjectNode envelope = mapper.createObjectNode();
            envelope.put("eventId", event.id().toString());
            envelope.put("eventType", event.type());
            envelope.put("aggregateId", event.aggregateId().toString());
            envelope.put("aggregateType", aggregateType);
            envelope.put("occurredAt", event.occurredAt().toString());
            envelope.put("version", 1);
            envelope.put("producer", "auth-service");
            envelope.set("payload", payload);
            ObjectNode metadata = envelope.putObject("metadata");
            metadata.put("correlationId", event.correlationId().toString());
            metadata.put("causationId", event.causationId().toString());
            metadata.putNull("actorUserId");
            return mapper.writeValueAsBytes(envelope);
        } catch (com.fasterxml.jackson.core.JsonProcessingException invalid) {
            throw new IllegalArgumentException("Invalid IAM event payload", invalid);
        }
    }
}
