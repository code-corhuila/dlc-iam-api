package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** User, role, audit, request key and UserRegistered outbox entry share one transaction. */
public interface RegistrationUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        boolean activeAdministratorForUpdate(UUID actorId);
        Attempt findAttempt(UUID idempotencyKey);
        boolean emailExists(String normalizedEmail);
        void createStaff(UUID userId, UUID actorId, String normalizedEmail, String passwordHash,
                         String name, String role, Instant at);
        void createVerificationChallenge(UUID challengeId, UUID userId, String tokenHash,
                                         Instant createdAt, Instant expiresAt);
        void appendAudit(UUID userId, UUID actorId, UUID correlationId, Instant at);
        void appendUserRegistered(UUID userId, UUID actorId, UUID correlationId, Instant at);
        void rememberAttempt(UUID key, UUID actorId, byte[] proof, Staff staff);
    }

    record Staff(UUID id, String email, String name, String role, String status,
                 Instant createdAt, long version) { }
    record Attempt(UUID actorId, byte[] proof, Staff staff) { }
}
