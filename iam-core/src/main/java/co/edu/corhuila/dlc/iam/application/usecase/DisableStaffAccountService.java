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
            var attempt = store.findAttempt(idempotencyKey);
            var staff = store.findForUpdate(userId);
            if (staff == null) throw new NoSuchElementException("Staff not found");
            if (attempt != null) return replay(attempt, actorId, userId,
                expectedVersion, reason, staff);
            // A contender may have committed the same keyed request while the row lock was awaited.
            attempt = store.findAttempt(idempotencyKey);
            if (attempt != null) return replay(attempt, actorId, userId,
                expectedVersion, reason, staff);
            if (staff.name() == null || staff.name().isBlank()) {
                throw new ConcurrentModificationException("Staff name must be set before disabling");
            }
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
            return result(staff, "DISABLED", at, expectedVersion + 1);
        });
    }

    private static Result replay(DisableStaffUnitOfWork.Attempt attempt, UUID actorId,
                                 UUID userId, long expectedVersion, String reason,
                                 DisableStaffUnitOfWork.Account staff) {
        if (!attempt.actorId().equals(actorId) || !attempt.userId().equals(userId)
            || attempt.expectedVersion() != expectedVersion || !attempt.reason().equals(reason)) {
            throw new ConcurrentModificationException("Idempotency key reused");
        }
        if (staff.version() != attempt.resultVersion() || !"DISABLED".equals(staff.status())
            || staff.name() == null || staff.name().isBlank()) {
            throw new ConcurrentModificationException("Staff changed after original disabling");
        }
        return result(staff, staff.status(), staff.updatedAt(), staff.version());
    }

    private static Result result(DisableStaffUnitOfWork.Account staff, String status,
                                 java.time.Instant updatedAt, long version) {
        return new Result(staff.userId(), staff.email(), staff.name(), staff.roles(), status,
            staff.createdAt(), updatedAt, version);
    }
}
