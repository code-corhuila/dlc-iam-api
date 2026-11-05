package co.edu.corhuila.dlc.iam.application.port.in;

import java.util.UUID;
import java.util.List;
import java.time.Instant;

public interface DisableStaffAccount {
    Result disable(UUID actorId, UUID userId, long expectedVersion, String reason,
                   UUID idempotencyKey, UUID correlationId);

    record Result(UUID id, String email, String name, List<String> roles, String status,
                  Instant createdAt, Instant updatedAt, long version) { }
}
