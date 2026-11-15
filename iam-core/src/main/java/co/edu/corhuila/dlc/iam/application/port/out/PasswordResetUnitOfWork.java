package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** Challenge consumption, password replacement, revocation and outbox append share one transaction. */
public interface PasswordResetUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        Challenge findForUpdate(String tokenHash, String purpose);
        boolean consume(UUID challengeId, Instant at);
        /** Changes only the hash and version, never account eligibility. */
        boolean changePassword(UUID userId, String passwordHash, Instant at);
        /** Revokes active sessions and appends one approved SessionRevoked event per session. */
        void revokeSessions(UUID userId, UUID correlationId, Instant at);
    }

    record Challenge(UUID id, UUID userId, String purpose, Instant expiresAt,
                     Instant consumedAt) { }
}
