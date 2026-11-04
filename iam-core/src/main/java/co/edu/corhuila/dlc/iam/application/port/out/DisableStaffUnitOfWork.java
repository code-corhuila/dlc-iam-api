package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/** The account update, audit, and SessionRevoked outbox entries share one transaction. */
public interface DisableStaffUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        boolean activeAdministratorForUpdate(UUID actorId);
        Attempt findAttempt(UUID idempotencyKey);
        Account findForUpdate(UUID userId);
        List<UUID> activeSessionsForUpdate(UUID userId);
        void disable(UUID userId, long expectedVersion, Instant at);
        void appendAudit(UUID userId, UUID actorId, String priorStatus, String reason,
                         long expectedVersion, UUID idempotencyKey, UUID correlationId, Instant at);
        void appendSessionRevoked(UUID sessionId, UUID userId, UUID actorId,
                                  UUID correlationId, Instant at);
    }

    record Account(UUID userId, String status, long version, List<String> roles) { }
    record Attempt(UUID actorId, UUID userId, String reason,
                   long expectedVersion, long resultVersion) { }
}
