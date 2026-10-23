package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import co.edu.corhuila.dlc.iam.application.port.out.UnlockUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class UnlockStaffService {
    private final UnlockUnitOfWork unitOfWork;
    private final Clock clock;

    public UnlockStaffService(UnlockUnitOfWork unitOfWork, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.clock = clock;
    }

    public LoginUseCase.Staff unlock(UUID actorId, UUID sessionId,
                                     UUID targetId, UUID correlationId) {
        if (actorId == null || sessionId == null || targetId == null
            || correlationId == null) throw new IllegalArgumentException("Missing unlock input");
        Instant now = clock.instant();
        return unitOfWork.execute(store -> {
            if (!store.isCurrentAdministrator(actorId, sessionId, now))
                throw new Forbidden();
            var target = store.findForUpdate(targetId);
            if (target == null) throw new NotFound();
            if (!"LOCKED".equals(target.status()))
                throw new IllegalArgumentException("Only locked staff can be unlocked");
            store.unlock(target, actorId, correlationId, now);
            return new LoginUseCase.Staff(target.id(), target.email(), target.name(),
                List.copyOf(target.roles()), "ACTIVE", target.version() + 1);
        });
    }

    public static final class Forbidden extends RuntimeException { }
    public static final class NotFound extends RuntimeException { }
}
