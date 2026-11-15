package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/** All store operations execute in one database transaction. */
public interface StaffNameUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        boolean activeAdministrator(UUID actorId);
        Staff findForUpdate(UUID userId);
        void updateName(UUID userId, String name, long expectedVersion, Instant at);
        void appendAudit(UUID userId, UUID actorId, String status, UUID correlationId, Instant at);
    }

    record Staff(UUID id, String email, String name, List<String> roles, String status,
                 Instant createdAt, Instant updatedAt, long version) { }
}
