package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.EnableStaffAccount;
import co.edu.corhuila.dlc.iam.application.port.out.EnableStaffUnitOfWork;
import java.time.Clock;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import java.util.UUID;

public final class EnableStaffAccountService implements EnableStaffAccount {
    private final EnableStaffUnitOfWork unitOfWork;
    private final Clock clock;

    public EnableStaffAccountService(EnableStaffUnitOfWork unitOfWork, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.clock = clock;
    }

    @Override
    public Result enable(UUID actorId, UUID userId, long expectedVersion, String reason,
                         UUID idempotencyKey, UUID correlationId) {
        if (actorId == null || userId == null || idempotencyKey == null || correlationId == null
            || expectedVersion < 1 || reason == null || reason.isBlank()
            || !reason.equals(reason.strip()) || reason.length() > 1000) {
            throw new IllegalArgumentException("Invalid staff enabling request");
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
            // Recheck after the row lock: a contender may have committed this key while waiting.
            replay = replay(store.findAttempt(idempotencyKey), actorId, userId,
                expectedVersion, reason);
            if (replay != null) return replay;
            if (staff.roles().contains("ADMINISTRATOR")) {
                throw new SecurityException("Bootstrap Administrator cannot be enabled here");
            }
            if (staff.version() != expectedVersion || !"DISABLED".equals(staff.status())) {
                throw new ConcurrentModificationException("Staff state or version changed");
            }
            var nextStatus = staff.verified() ? "ACTIVE" : "PENDING_VERIFICATION";
            var at = clock.instant();
            store.enable(userId, expectedVersion, nextStatus, at);
            store.appendAudit(userId, actorId, nextStatus, reason, expectedVersion,
                idempotencyKey, correlationId, at);
            return new Result(userId, nextStatus, expectedVersion + 1);
        });
    }

    private static Result replay(EnableStaffUnitOfWork.Attempt attempt, UUID actorId,
                                 UUID userId, long expectedVersion, String reason) {
        if (attempt == null) return null;
        if (!attempt.actorId().equals(actorId) || !attempt.userId().equals(userId)
            || attempt.expectedVersion() != expectedVersion || !attempt.reason().equals(reason)) {
            throw new ConcurrentModificationException("Idempotency key reused");
        }
        return new Result(userId, attempt.nextStatus(), attempt.resultVersion());
    }
}
