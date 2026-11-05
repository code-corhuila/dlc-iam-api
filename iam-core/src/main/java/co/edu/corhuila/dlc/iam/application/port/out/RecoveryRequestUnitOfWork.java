package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** Challenge creation and durable delivery scheduling must commit together. */
public interface RecoveryRequestUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        /** Returns only verified IAM staff; null for unknown or unverified accounts. */
        UUID verifiedUserForUpdate(String normalizedEmail);
        void createChallenge(UUID challengeId, UUID userId, String purpose,
                             String tokenHash, Instant createdAt, Instant expiresAt);
        /** Queue a protected message; raw tokens must never be persisted in plaintext. */
        void queueDelivery(UUID userId, String normalizedEmail, String rawToken,
                           UUID correlationId);
    }
}
