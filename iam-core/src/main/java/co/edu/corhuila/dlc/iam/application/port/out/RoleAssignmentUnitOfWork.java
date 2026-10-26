package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/** All Store operations run in one transaction; a failure rolls them all back. */
public interface RoleAssignmentUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        boolean activeAdministratorForUpdate(UUID actorId);
        StaffAccount findForUpdate(UUID userId);
        void replaceRoles(UUID userId, List<String> roles, long expectedVersion);
        void appendAudit(UUID userId, String role, String action, UUID actorId,
                         String reason, UUID correlationId, Instant at);
        void appendRoleEvent(String eventType, UUID userId, String role,
                             UUID actorId, UUID correlationId, Instant at);
        /** Revoke active sessions and append their approved SessionRevoked events. */
        void revokeSessions(UUID userId, UUID actorId, UUID correlationId, Instant at);
    }

    record StaffAccount(UUID id, String email, String name, String status,
                        long version, List<String> roles) { }
}
