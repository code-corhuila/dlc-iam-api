package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

public interface LoginUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        StaffAccount findForUpdate(String normalizedEmail);
        void recordFailedPassword(StaffAccount staff, Instant at, UUID correlationId);
        StaffAccount unlockExpired(StaffAccount staff, Instant at, UUID correlationId);
        void resetFailures(UUID userId, Instant at);
        void createSession(UUID sessionId, UUID userId, String deviceId,
                           Instant at, Instant inactiveAt);
        void createRefresh(UUID familyId, UUID sessionId, UUID credentialId,
                           String tokenHash, Instant at, Instant expiresAt);
        void appendSessionStarted(UUID eventId, UUID correlationId, UUID sessionId,
                                  UUID userId, String deviceId, Instant at,
                                  Instant expiresAt);
    }

    record StaffAccount(UUID id, String email, String name, String passwordHash,
                        String status, Instant verifiedAt, int failedAttempts,
                        Instant lockedUntil, long version,
                        List<String> roles) { }
}
