package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** Challenge consumption, account activation and outbox append are one transaction. */
public interface EmailVerificationUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        Challenge findForUpdate(String tokenHash, String purpose);
        /** Returns false if another transaction consumed the challenge. */
        boolean consume(UUID challengeId, Instant at);
        /** Sets ACTIVE and email_verified_at only for PENDING_VERIFICATION. */
        boolean activatePendingUser(UUID userId, Instant at);
        void appendUserEmailVerified(UUID eventId, UUID userId,
                                     UUID correlationId, Instant at);
    }

    record Challenge(UUID id, UUID userId, String purpose, Instant expiresAt,
                     Instant consumedAt) { }
}
