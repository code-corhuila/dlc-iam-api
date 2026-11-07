package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/** Credential lookup, session revocation and events share one transaction. */
public interface LogoutUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        Credential findForUpdate(String tokenHash);
        /** Return only active sessions of this owner; lock them before any writes. */
        List<UUID> activeSessionsForUpdate(UUID userId, UUID currentId, boolean allDevices);
        boolean revokeSession(UUID userId, UUID sessionId, Instant at);
        void appendSessionRevoked(UUID eventId, UUID userId, UUID sessionId,
                                  UUID correlationId, Instant at);
    }

    record Credential(UUID userId, UUID sessionId, Instant expiresAt,
                      Instant consumedAt, Instant revokedAt, Instant familyRevokedAt,
                      Instant sessionRevokedAt, Instant inactivityExpiresAt) { }
}
