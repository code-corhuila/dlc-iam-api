package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/** Every Store operation, including reuse revocation and outbox, shares one transaction. */
public interface RefreshRotationUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        Credential findForUpdate(String tokenHash);
        boolean rotate(UUID credentialId, UUID replacementId, String replacementHash,
                       Instant at, Instant expiresAt);
        /** Revoke the family and append one approved SessionRevoked event atomically. */
        void revokeReusedFamily(UUID familyId, UUID sessionId, UUID userId,
                                UUID correlationId, Instant at);
    }

    record Credential(UUID id, UUID familyId, UUID sessionId, Instant expiresAt,
                      Instant consumedAt, Instant revokedAt, Instant familyRevokedAt,
                      Instant sessionRevokedAt, Instant inactivityExpiresAt,
                      LoginUnitOfWork.StaffAccount staff) { }
}
