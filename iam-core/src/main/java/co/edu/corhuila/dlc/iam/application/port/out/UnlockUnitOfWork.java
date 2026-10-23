package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

public interface UnlockUnitOfWork {
    <T> T execute(Function<Store, T> operation);

    interface Store {
        boolean isCurrentAdministrator(UUID actorId, UUID sessionId, Instant now);
        Staff findForUpdate(UUID userId);
        void unlock(Staff staff, UUID actorId, UUID correlationId, Instant now);
    }

    record Staff(UUID id, String email, String name, String status,
                 long version, List<String> roles) { }
}
