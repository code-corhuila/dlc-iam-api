package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionRevocationUnitOfWork;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.NoSuchElementException;
import java.util.UUID;

public final class RevokeOwnSessionService {
    private final OwnSessionRevocationUnitOfWork unitOfWork;
    private final Clock clock;

    public RevokeOwnSessionService(OwnSessionRevocationUnitOfWork unitOfWork, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.clock = clock;
    }

    public void revoke(UUID ownerId, UUID sessionId, UUID idempotencyKey,
                       String reason, UUID correlationId) {
        if (ownerId == null || sessionId == null || idempotencyKey == null
            || correlationId == null || reason == null || reason.isBlank()
            || reason.length() > 1000) {
            throw new IllegalArgumentException("Invalid session revocation request");
        }
        // The outbox primary key records one owner-scoped key for this operation.
        UUID eventId = UUID.nameUUIDFromBytes(("revoke-own-session:" + ownerId + ":"
            + idempotencyKey).getBytes(StandardCharsets.UTF_8));
        unitOfWork.execute(store -> {
            var session = store.findForUpdate(sessionId, ownerId);
            if (session == null) throw new NoSuchElementException("Session not found");
            // Authenticate and verify ownership before replaying a stored result.
            var prior = store.findAttempt(eventId);
            if (prior != null) {
                replay(prior, ownerId, sessionId, reason);
                return null;
            }
            var now = clock.instant();
            if (session.revoked() || !store.revoke(sessionId, ownerId, reason, now)) {
                throw new SessionRevocationConflictException(
                    "SESSION_CONFLICT", "Session already revoked");
            }
            store.appendEvent(eventId, sessionId, ownerId, reason,
                correlationId, idempotencyKey, now);
            return null;
        });
    }

    private static void replay(OwnSessionRevocationUnitOfWork.Attempt prior,
                               UUID ownerId, UUID sessionId, String reason) {
        if (!prior.ownerId().equals(ownerId) || !prior.sessionId().equals(sessionId)
            || !prior.reason().equals(reason)) {
            throw new SessionRevocationConflictException(
                "IDEMPOTENCY_CONFLICT", "Idempotency key already used for another request");
        }
    }
}
