package co.edu.corhuila.dlc.iam.application.port.in;

import java.util.UUID;

public interface EnableStaffAccount {
    Result enable(UUID actorId, UUID userId, long expectedVersion, String reason,
                  UUID idempotencyKey, UUID correlationId);

    record Result(UUID userId, String status, long version) { }
}
