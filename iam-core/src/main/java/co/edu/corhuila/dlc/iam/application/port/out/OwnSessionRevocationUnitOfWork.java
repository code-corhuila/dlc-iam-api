package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** Session state and outbox are changed in one database transaction. */
public interface OwnSessionRevocationUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        Attempt findAttempt(UUID eventId);
        Session findForUpdate(UUID sessionId, UUID ownerId);
        boolean revoke(UUID sessionId, UUID ownerId, String reason, Instant at);
        void appendEvent(UUID eventId, UUID sessionId, UUID ownerId, String reason,
                         UUID correlationId, UUID idempotencyKey, Instant at);
    }

    record Attempt(UUID sessionId, UUID ownerId, String reason) { }
    record Session(boolean revoked) { }
}
