package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.DisableStaffAccount;
import co.edu.corhuila.dlc.iam.application.port.out.DisableStaffUnitOfWork;
import java.time.Clock;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import java.util.UUID;

public final class DisableStaffAccountService implements DisableStaffAccount {
    private final DisableStaffUnitOfWork unitOfWork;
    private final Clock clock;

    public DisableStaffAccountService(DisableStaffUnitOfWork unitOfWork, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.clock = clock;
    }

    @Override
    public Result disable(UUID actorId, UUID userId, long expectedVersion, String reason,
                          UUID idempotencyKey, UUID correlationId) {
        if (actorId == null || userId == null || idempotencyKey == null || correlationId == null
            || expectedVersion < 1 || reason == null || reason.isBlank()
            || !reason.equals(reason.strip()) || reason.length() > 1000) {
            throw new IllegalArgumentException("Invalid staff disabling request");
        }
        return unitOfWork.execute(store -> {
            if (!store.activeAdministratorForUpdate(actorId)) {
                throw new SecurityException("Administrator required");
            }
            var replay = replay(store.findAttempt(idempotencyKey), actorId, userId,
                expectedVersion, reason);
            if (replay != null) return replay;
            var staff = store.findForUpdate(userId);
            if (staff == null) throw new NoSuchElementException("Staff not found");
            // A contender may have committed the same keyed request while the row lock was awaited.
            replay = replay(store.findAttempt(idempotencyKey), actorId, userId,
                expectedVersion, reason);
            if (replay != null) return replay;
            if (staff.roles().contains("ADMINISTRATOR")) {
                throw new SecurityException("Bootstrap Administrator cannot be disabled here");
            }
            if (staff.version() != expectedVersion || "DISABLED".equals(staff.status())) {
                throw new ConcurrentModificationException("Staff state or version changed");
            }
            var at = clock.instant();
            var sessions = store.activeSessionsForUpdate(userId);
            store.disable(userId, expectedVersion, at);
            store.appendAudit(userId, actorId, staff.status(), reason, expectedVersion,
                idempotencyKey, correlationId, at);
            for (UUID sessionId : sessions) {
                store.appendSessionRevoked(sessionId, userId, actorId, correlationId, at);
            }
            return new Result(userId, "DISABLED", expectedVersion + 1);
        });
    }

    private static Result replay(DisableStaffUnitOfWork.Attempt attempt, UUID actorId,
                                 UUID userId, long expectedVersion, String reason) {
        if (attempt == null) return null;
        if (!attempt.actorId().equals(actorId) || !attempt.userId().equals(userId)
            || attempt.expectedVersion() != expectedVersion || !attempt.reason().equals(reason)) {
            throw new ConcurrentModificationException("Idempotency key reused");
        }
        return new Result(userId, "DISABLED", attempt.resultVersion());
    }
}
