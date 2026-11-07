package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.application.port.out.LogoutUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class LogoutServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-02T10:00:00Z");
    private static final UUID OWNER = UUID.randomUUID();
    private static final UUID CURRENT = UUID.randomUUID();
    private static final UUID OTHER = UUID.randomUUID();
    private final FakeStore store = new FakeStore();
    private final LogoutService service = new LogoutService(store, new RefreshCredential() {
        public String generate() { throw new AssertionError("Logout must not issue a token"); }
        public String hash(String raw) { return "hash:" + raw; }
    }, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void currentDeviceLogoutRevokesOnlyCookieSessionAndEmitsOneEvent() {
        store.credential = credential();
        service.logout("opaque-refresh", false, UUID.randomUUID());
        assertEquals("hash:opaque-refresh", store.lookupHash);
        assertEquals(List.of(CURRENT), store.revoked);
        assertEquals(List.of(CURRENT), store.events);
        assertTrue(store.completed);
    }

    @Test
    void allDevicesRevokesOnlyAuthenticatedUsersActiveSessions() {
        store.credential = credential();
        service.logout("opaque-refresh", true, UUID.randomUUID());
        assertEquals(List.of(CURRENT, OTHER), store.revoked);
        assertEquals(store.revoked, store.events);
        assertEquals(OWNER, store.owner);
    }

    @Test
    void missingExpiredAndReusedCookieFailWithoutChanges() {
        assertThrows(InvalidLoginException.class,
            () -> service.logout("unknown", false, UUID.randomUUID()));
        store.credential = new LogoutUnitOfWork.Credential(OWNER, CURRENT, NOW,
            null, null, null, null, NOW.plusSeconds(60));
        assertThrows(InvalidLoginException.class,
            () -> service.logout("opaque-refresh", false, UUID.randomUUID()));
        store.credential = new LogoutUnitOfWork.Credential(OWNER, CURRENT,
            NOW.plusSeconds(60), NOW, null, null, null, NOW.plusSeconds(60));
        assertThrows(InvalidLoginException.class,
            () -> service.logout("opaque-refresh", false, UUID.randomUUID()));
        assertEquals(List.of(), store.revoked);
        assertEquals(List.of(), store.events);
    }

    @Test
    void malformedInputNeverTouchesStore() {
        assertThrows(IllegalArgumentException.class,
            () -> service.logout("", false, UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class,
            () -> service.logout("opaque-refresh", true, null));
        assertEquals(0, store.lookups);
    }

    private static LogoutUnitOfWork.Credential credential() {
        return new LogoutUnitOfWork.Credential(OWNER, CURRENT, NOW.plusSeconds(60),
            null, null, null, null, NOW.plusSeconds(60));
    }

    private static final class FakeStore implements LogoutUnitOfWork, LogoutUnitOfWork.Store {
        LogoutUnitOfWork.Credential credential;
        String lookupHash;
        UUID owner;
        int lookups;
        boolean completed;
        final List<UUID> revoked = new ArrayList<>();
        final List<UUID> events = new ArrayList<>();

        public <T> T execute(Function<Store, T> operation) {
            completed = false;
            T result = operation.apply(this);
            completed = true;
            return result;
        }

        public LogoutUnitOfWork.Credential findForUpdate(String tokenHash) {
            lookups++;
            lookupHash = tokenHash;
            return credential;
        }

        public List<UUID> activeSessionsForUpdate(UUID userId, UUID currentId,
                                                  boolean allDevices) {
            owner = userId;
            return allDevices ? List.of(CURRENT, OTHER) : List.of(CURRENT);
        }

        public boolean revokeSession(UUID userId, UUID sessionId, Instant at) {
            revoked.add(sessionId);
            return true;
        }

        public void appendSessionRevoked(UUID eventId, UUID userId, UUID sessionId,
                                         UUID correlationId, Instant at) {
            events.add(sessionId);
        }
    }
}
