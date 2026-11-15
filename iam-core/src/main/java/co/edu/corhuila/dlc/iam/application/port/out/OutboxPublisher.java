package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;

/** Returns only after the broker confirms durable acceptance. */
public interface OutboxPublisher {
    void publish(Event event);

    record Event(UUID id, String type, UUID aggregateId, UUID correlationId,
                 UUID causationId, String payloadJson, Instant occurredAt) { }
}
