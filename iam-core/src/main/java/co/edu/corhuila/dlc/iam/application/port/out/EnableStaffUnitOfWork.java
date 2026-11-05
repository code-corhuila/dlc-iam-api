package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/** Enabling and its correlated audit record must commit or roll back together. */
public interface EnableStaffUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        boolean activeAdministratorForUpdate(UUID actorId);
        Attempt findAttempt(UUID idempotencyKey);
        Account findForUpdate(UUID userId);
        void enable(UUID userId, long expectedVersion, String nextStatus, Instant at);
        void appendAudit(UUID userId, UUID actorId, String nextStatus, String reason,
                         long expectedVersion, UUID idempotencyKey, UUID correlationId, Instant at);
    }

    record Account(UUID userId, String email, String name, String status, boolean verified,
                   Instant createdAt, Instant updatedAt, long version, List<String> roles) { }
    record Attempt(UUID actorId, UUID userId, String reason, long expectedVersion,
                   String nextStatus, long resultVersion) { }
}
