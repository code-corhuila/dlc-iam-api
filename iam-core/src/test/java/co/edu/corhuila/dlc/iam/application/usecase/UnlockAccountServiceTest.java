package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.UnlockAccountUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class UnlockAccountServiceTest {
    private final UUID admin = UUID.randomUUID();
    private final UUID staff = UUID.randomUUID();
    private final UUID key = UUID.randomUUID();
    private final UUID correlation = UUID.randomUUID();
    private final Instant now = Instant.parse("2026-11-04T12:00:00Z");
    private final FakeUnitOfWork store = new FakeUnitOfWork();
    private final UnlockAccountService service = new UnlockAccountService(store,
        Clock.fixed(now, ZoneOffset.UTC));

    @Test
    void unlocksOnlyVerifiedLockedStaffAndRecordsOneEvent() {
        var result = service.unlock(admin, staff, 4, "Administrator reviewed lock", key, correlation);
        assertEquals("ACTIVE", result.status());
        assertEquals("Ada Staff", result.name());
        assertEquals(List.of("DENTIST"), result.roles());
        assertEquals(now, result.updatedAt());
        assertEquals(5, result.version());
        assertEquals(1, store.stateWrites);
        assertEquals(1, store.audits);
        assertEquals(1, store.events);
        assertEquals("Administrator reviewed lock", store.reason);
        assertEquals(correlation, store.correlation);
        assertEquals(now, store.occurredAt);
    }

    @Test
    void exactRetryReturnsOriginalResultWithoutNewEffects() {
        store.attempt = new UnlockAccountUnitOfWork.Attempt(admin, staff,
            "Administrator reviewed lock", 4, 5);
        store.account = account("ACTIVE", true, 5);
        var result = service.unlock(admin, staff, 4, "Administrator reviewed lock", key, correlation);
        assertEquals(5, result.version());
        assertEquals(0, store.stateWrites);
        assertEquals(0, store.audits);
        assertEquals(0, store.events);
    }

    @Test
    void retryThatCommitsWhileWaitingForTargetLockReturnsOriginalResult() {
        store.lateAttempt = new UnlockAccountUnitOfWork.Attempt(admin, staff,
            "Administrator reviewed lock", 4, 5);
        store.account = account("ACTIVE", true, 5);
        var result = service.unlock(admin, staff, 4, "Administrator reviewed lock", key, correlation);
        assertEquals(5, result.version());
        assertEquals(0, store.stateWrites);
        assertEquals(0, store.audits);
    }

    @Test
    void rejectsKeyReuseForDifferentRequest() {
        store.attempt = new UnlockAccountUnitOfWork.Attempt(admin, staff, "Original", 4, 5);
        assertThrows(ConcurrentModificationException.class,
            () -> service.unlock(admin, staff, 4, "Changed", key, correlation));
        assertEquals(0, store.stateWrites);
    }

    @Test
    void rejectsNonAdminMissingDisabledUnverifiedAndStaleStaff() {
        store.admin = false;
        assertThrows(SecurityException.class,
            () -> service.unlock(admin, staff, 4, "Reason", key, correlation));
        store.admin = true;
        store.account = null;
        assertThrows(NoSuchElementException.class,
            () -> service.unlock(admin, staff, 4, "Reason", key, correlation));
        for (var account : new UnlockAccountUnitOfWork.Account[] {
            account("DISABLED", true, 4),
            account("PENDING_VERIFICATION", false, 4),
            account("LOCKED", false, 4),
            account("LOCKED", true, 5)
        }) {
            store.account = account;
            assertThrows(ConcurrentModificationException.class,
                () -> service.unlock(admin, staff, 4, "Reason", key, correlation));
        }
        assertEquals(0, store.stateWrites);
    }

    @Test
    void rejectsMalformedInputsBeforeOpeningTransaction() {
        for (String reason : new String[] {"", " ", " Leading", "Trailing ", "x".repeat(1001)}) {
            assertThrows(IllegalArgumentException.class,
                () -> service.unlock(admin, staff, 4, reason, key, correlation));
        }
        assertThrows(IllegalArgumentException.class,
            () -> service.unlock(admin, staff, 0, "Reason", key, correlation));
        assertThrows(IllegalArgumentException.class,
            () -> service.unlock(admin, staff, 4, "Reason", null, correlation));
        assertEquals(0, store.executions);
    }

    @Test
    void failedEventAbortsStateAndAuditTransaction() {
        store.failEvent = true;
        assertThrows(IllegalStateException.class,
            () -> service.unlock(admin, staff, 4, "Reason", key, correlation));
        assertEquals(0, store.committedTransactions);
        assertEquals(0, store.stateWrites);
        assertEquals(0, store.audits);
    }

    @Test
    void missingLegacyNameRejectsBeforeAnyWrite() {
        store.account = new UnlockAccountUnitOfWork.Account(staff, "ada@example.test", null,
            List.of("DENTIST"), "LOCKED", now.minusSeconds(100), now, true, 4);
        assertThrows(ConcurrentModificationException.class,
            () -> service.unlock(admin, staff, 4, "Reason", key, correlation));
        assertEquals(0, store.stateWrites);
        assertEquals(0, store.audits);
    }

    @Test
    void oldReplayAfterFurtherAccountChangeConflicts() {
        store.attempt = new UnlockAccountUnitOfWork.Attempt(admin, staff, "Reason", 4, 5);
        store.account = account("ACTIVE", true, 7);
        assertThrows(ConcurrentModificationException.class,
            () -> service.unlock(admin, staff, 4, "Reason", key, correlation));
    }

    private UnlockAccountUnitOfWork.Account account(String status, boolean verified, long version) {
        return new UnlockAccountUnitOfWork.Account(staff, "ada@example.test", "Ada Staff",
            List.of("DENTIST"), status, now.minusSeconds(100), now.minusSeconds(10),
            verified, version);
    }

    private final class FakeUnitOfWork implements UnlockAccountUnitOfWork,
                                                  UnlockAccountUnitOfWork.Store {
        Account account = account("LOCKED", true, 4);
        Attempt attempt;
        Attempt lateAttempt;
        int attemptReads;
        boolean admin = true;
        boolean failEvent;
        int executions;
        int committedTransactions;
        int stateWrites;
        int audits;
        int events;
        String reason;
        UUID correlation;
        Instant occurredAt;

        @Override public <T> T execute(Function<Store, T> operation) {
            executions++;
            try {
                T result = operation.apply(this);
                committedTransactions++;
                return result;
            } catch (RuntimeException failed) {
                stateWrites = 0;
                audits = 0;
                throw failed;
            }
        }
        @Override public boolean activeAdministratorForUpdate(UUID actorId) { return admin; }
        @Override public Attempt findAttempt(UUID idempotencyKey) {
            attemptReads++;
            return attemptReads == 2 && lateAttempt != null ? lateAttempt : attempt;
        }
        @Override public Account findForUpdate(UUID userId) { return account; }
        @Override public void unlock(UUID userId, long version, Instant at) { stateWrites++; }
        @Override public void appendAudit(UUID userId, UUID actorId, String reason,
                                          long expectedVersion, long resultVersion,
                                          UUID idempotencyKey, UUID correlationId, Instant at) {
            audits++;
            this.reason = reason;
            correlation = correlationId;
            occurredAt = at;
        }
        @Override public void appendUserUnlocked(UUID userId, UUID actorId, UUID idempotencyKey,
                                                 UUID correlationId, Instant at) {
            if (failEvent) throw new IllegalStateException("Outbox unavailable");
            events++;
        }
    }
}
