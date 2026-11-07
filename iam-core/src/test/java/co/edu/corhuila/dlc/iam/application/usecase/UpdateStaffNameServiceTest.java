package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.StaffNameUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class UpdateStaffNameServiceTest {
    private final UUID actor = UUID.randomUUID();
    private final UUID staff = UUID.randomUUID();
    private final UUID correlation = UUID.randomUUID();
    private final FakeStore store = new FakeStore();
    private final UpdateStaffNameService service = new UpdateStaffNameService(store,
        Clock.fixed(Instant.parse("2026-11-04T12:00:00Z"), ZoneOffset.UTC));

    @Test
    void updatesNameAndAppendsAuditOnce() {
        var result = service.update(actor, staff, "Ada Lovelace", 1, correlation);
        assertEquals("Ada Lovelace", result.name());
        assertEquals(2, result.version());
        assertEquals(1, store.writes);
        assertEquals(1, store.audits);
        assertEquals(correlation, store.correlation);
    }

    @Test
    void unchangedNameDoesNotAdvanceVersionOrAudit() {
        var result = service.update(actor, staff, "Ada Staff", 1, correlation);
        assertEquals(1, result.version());
        assertEquals(0, store.writes);
        assertEquals(0, store.audits);
    }

    @Test
    void rejectsInvalidNameBeforeStorage() {
        for (String invalid : new String[] {"", " ", " Ada", "Ada ", "x".repeat(101)}) {
            assertThrows(IllegalArgumentException.class,
                () -> service.update(actor, staff, invalid, 1, correlation));
        }
        assertEquals(0, store.executions);
    }

    @Test
    void rejectsUnauthorizedMissingAndStaleUpdates() {
        store.admin = false;
        assertThrows(SecurityException.class,
            () -> service.update(actor, staff, "New Name", 1, correlation));
        store.admin = true;
        store.account = null;
        assertThrows(NoSuchElementException.class,
            () -> service.update(actor, staff, "New Name", 1, correlation));
        store.account = account(2);
        assertThrows(ConcurrentModificationException.class,
            () -> service.update(actor, staff, "New Name", 1, correlation));
        assertEquals(0, store.writes);
        assertEquals(0, store.audits);
    }

    private final class FakeStore implements StaffNameUnitOfWork, StaffNameUnitOfWork.Store {
        Staff account = account(1);
        boolean admin = true;
        int executions;
        int writes;
        int audits;
        UUID correlation;

        @Override
        public <T> T execute(Function<Store, T> operation) {
            executions++;
            return operation.apply(this);
        }

        @Override public boolean activeAdministrator(UUID actorId) { return admin; }
        @Override public Staff findForUpdate(UUID userId) { return account; }
        @Override public void updateName(UUID userId, String name, long version, Instant at) {
            writes++;
        }
        @Override public void appendAudit(UUID userId, UUID actorId, String status,
                                          UUID correlationId, Instant at) {
            audits++;
            correlation = correlationId;
        }
    }

    private StaffNameUnitOfWork.Staff account(long version) {
        return new StaffNameUnitOfWork.Staff(staff, "ada@example.test", "Ada Staff",
            List.of("DENTIST"), "ACTIVE", Instant.parse("2026-11-01T12:00:00Z"),
            Instant.parse("2026-11-01T12:00:00Z"), version);
    }
}
