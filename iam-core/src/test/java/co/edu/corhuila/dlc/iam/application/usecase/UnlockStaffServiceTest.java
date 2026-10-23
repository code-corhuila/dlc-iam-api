package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.UnlockUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class UnlockStaffServiceTest {
    private final UUID actor = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();
    private final UUID target = UUID.randomUUID();
    private final UUID correlation = UUID.randomUUID();
    private final Clock clock = Clock.fixed(Instant.parse("2026-10-23T12:00:00Z"),
        ZoneOffset.UTC);

    @Test
    void unlocksOnlyLockedStaffWithCurrentAdministrator() {
        var store = new FakeStore();
        var result = new UnlockStaffService(work(store), clock)
            .unlock(actor, session, target, correlation);
        assertEquals("ACTIVE", result.status());
        assertEquals(8, result.version());
        assertEquals(1, store.writes);
    }

    @Test
    void deniesRevokedActorAndWrongTargetStateWithoutWriting() {
        var store = new FakeStore();
        store.administrator = false;
        var service = new UnlockStaffService(work(store), clock);
        assertThrows(UnlockStaffService.Forbidden.class,
            () -> service.unlock(actor, session, target, correlation));
        store.administrator = true;
        store.status = "DISABLED";
        assertThrows(IllegalArgumentException.class,
            () -> service.unlock(actor, session, target, correlation));
        assertEquals(0, store.writes);
    }

    private UnlockUnitOfWork work(FakeStore store) {
        return new UnlockUnitOfWork() {
            @Override
            public <T> T execute(Function<Store, T> operation) {
                return operation.apply(store);
            }
        };
    }

    private final class FakeStore implements UnlockUnitOfWork.Store {
        boolean administrator = true;
        String status = "LOCKED";
        int writes;

        @Override
        public boolean isCurrentAdministrator(UUID id, UUID sid, Instant now) {
            return administrator && actor.equals(id) && session.equals(sid);
        }

        @Override
        public UnlockUnitOfWork.Staff findForUpdate(UUID id) {
            return new UnlockUnitOfWork.Staff(id, "staff@example.test", "Staff",
                status, 7, List.of("DENTIST"));
        }

        @Override
        public void unlock(UnlockUnitOfWork.Staff staff, UUID actorId,
                           UUID correlationId, Instant now) {
            writes++;
        }
    }
}
