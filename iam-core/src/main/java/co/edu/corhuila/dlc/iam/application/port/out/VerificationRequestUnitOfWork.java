package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** Stores only the verification hash; email delivery follows commit. */
public interface VerificationRequestUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        UUID pendingUserForUpdate(String normalizedEmail);
        void replaceChallenge(UUID challengeId, UUID userId, String tokenHash,
                              Instant createdAt, Instant expiresAt);
    }
}
