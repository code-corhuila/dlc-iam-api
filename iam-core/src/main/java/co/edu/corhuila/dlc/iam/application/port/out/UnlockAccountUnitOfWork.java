package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** One transaction covers account state, audit, and the approved owner event. */
public interface UnlockAccountUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        boolean activeAdministratorForUpdate(UUID actorId);
        Attempt findAttempt(UUID idempotencyKey);
        Account findForUpdate(UUID userId);
        void unlock(UUID userId, long expectedVersion, Instant at);
        void appendAudit(UUID userId, UUID actorId, String reason,
                         long expectedVersion, long resultVersion,
                         UUID idempotencyKey, UUID correlationId, Instant at);
        void appendUserUnlocked(UUID userId, UUID actorId, UUID idempotencyKey,
                                UUID correlationId, Instant at);
    }

    record Account(UUID userId, String status, boolean verified, long version) { }
    record Attempt(UUID actorId, UUID userId, String reason,
                   long expectedVersion, long resultVersion) { }
}
