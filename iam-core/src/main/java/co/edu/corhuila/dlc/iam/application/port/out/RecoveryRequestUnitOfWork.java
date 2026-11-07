package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** Commits only the hash-stored IAM challenge; delivery happens after commit. */
public interface RecoveryRequestUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        /** Returns only verified IAM staff; null for unknown or unverified accounts. */
        UUID verifiedUserForUpdate(String normalizedEmail);
        /** Replaces any unused recovery challenge for this user in the same transaction. */
        void createChallenge(UUID challengeId, UUID userId, String purpose,
                             String tokenHash, Instant createdAt, Instant expiresAt);
    }
}
