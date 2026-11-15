package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.UnlockAccount;
import co.edu.corhuila.dlc.iam.application.port.out.UnlockAccountUnitOfWork;
import java.time.Clock;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import java.util.UUID;

public final class UnlockAccountService implements UnlockAccount {
    private final UnlockAccountUnitOfWork unitOfWork;
    private final Clock clock;

    public UnlockAccountService(UnlockAccountUnitOfWork unitOfWork, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.clock = clock;
    }

    @Override
    public Result unlock(UUID actorId, UUID userId, long expectedVersion, String reason,
                         UUID idempotencyKey, UUID correlationId) {
        if (actorId == null || userId == null || idempotencyKey == null || correlationId == null
            || expectedVersion < 1 || reason == null || reason.isBlank()
            || !reason.equals(reason.strip()) || reason.length() > 1000) {
            throw new IllegalArgumentException("Invalid unlock request");
        }
        return unitOfWork.execute(store -> {
            if (!store.activeAdministratorForUpdate(actorId)) {
                throw new SecurityException("Administrator required");
            }
            var previous = store.findAttempt(idempotencyKey);
            var account = store.findForUpdate(userId);
            if (account == null) {
                throw new NoSuchElementException("Staff not found");
            }
            if (previous != null) {
                return replay(previous, actorId, userId, expectedVersion, reason, account);
            }
            // A concurrent request with the same key may have committed while row locking waited.
            previous = store.findAttempt(idempotencyKey);
            if (previous != null) {
                return replay(previous, actorId, userId, expectedVersion, reason, account);
            }
            // Existing accounts may predate display_name. Return a contract-valid Staff or roll back.
            if (account.name() == null || account.name().isBlank()) {
                throw new ConcurrentModificationException("Staff name must be set before unlock");
            }
            if (account.version() != expectedVersion || !"LOCKED".equals(account.status())
                || !account.verified()) {
                throw new ConcurrentModificationException("Staff is not eligible for unlock");
            }
            var now = clock.instant();
            store.unlock(userId, expectedVersion, now);
            store.appendAudit(userId, actorId, reason, expectedVersion, expectedVersion + 1,
                idempotencyKey, correlationId, now);
            store.appendUserUnlocked(userId, actorId, idempotencyKey, correlationId, now);
            return result(account, "ACTIVE", now, expectedVersion + 1);
        });
    }

    private static Result replay(UnlockAccountUnitOfWork.Attempt previous, UUID actorId,
                                 UUID userId, long expectedVersion, String reason,
                                 UnlockAccountUnitOfWork.Account account) {
        if (!previous.actorId().equals(actorId) || !previous.userId().equals(userId)
            || previous.expectedVersion() != expectedVersion
            || !previous.reason().equals(reason)) {
            throw new ConcurrentModificationException("Idempotency key reused");
        }
        if (account.version() != previous.resultVersion() || !"ACTIVE".equals(account.status())
            || account.name() == null || account.name().isBlank()) {
            throw new ConcurrentModificationException("Staff changed after original unlock");
        }
        return result(account, account.status(), account.updatedAt(), account.version());
    }

    private static Result result(UnlockAccountUnitOfWork.Account account, String status,
                                 java.time.Instant updatedAt, long version) {
        return new Result(account.userId(), account.email(), account.name(), account.roles(),
            status, account.createdAt(), updatedAt, version);
    }
}
