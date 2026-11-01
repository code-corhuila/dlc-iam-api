package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionRevocationUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class RevokeOwnSessionServiceTest {
    private static final UUID OWNER = UUID.randomUUID();
    private static final UUID SESSION = UUID.randomUUID();
    private static final UUID KEY = UUID.randomUUID();
    private static final UUID CORRELATION = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-11-01T12:00:00Z");
    private final FakeStore store = new FakeStore();
    private final RevokeOwnSessionService service = new RevokeOwnSessionService(store,
        Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void revokesAndAppendsOneEventAndReplaysSameRequest() {
        service.revoke(OWNER, SESSION, KEY, "User request", CORRELATION);
        service.revoke(OWNER, SESSION, KEY, "User request", UUID.randomUUID());
        assertEquals(1, store.revocations);
        assertEquals(1, store.events);
        assertEquals(NOW, store.at);
        assertEquals(KEY, store.key);
    }

    @Test
    void keyCannotBeReusedForAnotherReasonOrSession() {
        service.revoke(OWNER, SESSION, KEY, "User request", CORRELATION);
        assertThrows(IllegalStateException.class,
            () -> service.revoke(OWNER, SESSION, KEY, "Other", CORRELATION));
        assertThrows(IllegalStateException.class,
            () -> service.revoke(OWNER, UUID.randomUUID(), KEY, "User request", CORRELATION));
        assertEquals(1, store.events);
    }

    @Test
    void foreignOrMissingSessionIsNotRevealed() {
        store.owned = false;
        assertThrows(NoSuchElementException.class,
            () -> service.revoke(OWNER, SESSION, KEY, "User request", CORRELATION));
        assertEquals(0, store.revocations);
    }

    @Test
    void alreadyRevokedWithNewKeyAndMalformedRequestsFail() {
        store.revoked = true;
        assertThrows(IllegalStateException.class,
            () -> service.revoke(OWNER, SESSION, KEY, "User request", CORRELATION));
        assertThrows(IllegalArgumentException.class,
            () -> service.revoke(OWNER, SESSION, KEY, " ", CORRELATION));
        assertEquals(0, store.events);
    }

    private static final class FakeStore implements OwnSessionRevocationUnitOfWork,
                                                    OwnSessionRevocationUnitOfWork.Store {
        Attempt attempt;
        boolean owned = true;
        boolean revoked;
        int revocations;
        int events;
        Instant at;
        UUID key;

        public <T> T execute(Function<Store, T> operation) { return operation.apply(this); }
        public Attempt findAttempt(UUID eventId) { return attempt; }
        public Session findForUpdate(UUID sessionId, UUID ownerId) {
            return owned ? new Session(revoked) : null;
        }
        public boolean revoke(UUID sessionId, UUID ownerId, String reason, Instant when) {
            revocations++;
            revoked = true;
            at = when;
            return true;
        }
        public void appendEvent(UUID eventId, UUID sessionId, UUID ownerId, String reason,
                                UUID correlationId, UUID idempotencyKey, Instant when) {
            events++;
            key = idempotencyKey;
            attempt = new Attempt(sessionId, ownerId, reason);
        }
    }
}
