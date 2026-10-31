package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.SessionSnapshotReader;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CurrentActorServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-31T12:00:00Z");
    private final UUID user = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final AccessTokenVerifier verifier = token -> {
        if (!"valid".equals(token)) throw new IllegalArgumentException();
        return new AccessTokenVerifier.VerifiedAccessToken(user, session,
            List.of("ADMINISTRATOR"));
    };

    @Test
    void acceptsOnlyCurrentEligibleActor() {
        var current = service((userId, sessionId) -> {
            assertEquals(user, userId);
            assertEquals(session, sessionId);
            return snapshot("ACTIVE", null, List.of("ADMINISTRATOR"));
        });
        var actor = current.authenticate("Bearer valid");
        assertEquals(user, actor.userId());
        assertEquals(List.of("ADMINISTRATOR"), actor.roles());
    }

    @Test
    void rejectsRevokedDisabledOrChangedRoleWithoutTrustingJwtAlone() {
        for (var state : List.of(
            snapshot("DISABLED", null, List.of("ADMINISTRATOR")),
            snapshot("ACTIVE", NOW, List.of("ADMINISTRATOR")),
            snapshot("ACTIVE", null, List.of("DENTIST")))) {
            assertThrows(InvalidLoginException.class,
                () -> service((id, sid) -> state).authenticate("Bearer valid"));
        }
        assertThrows(InvalidLoginException.class,
            () -> service((id, sid) -> null).authenticate("Bearer valid"));
        assertThrows(InvalidLoginException.class,
            () -> service((id, sid) -> snapshot("ACTIVE", null,
                List.of("ADMINISTRATOR"))).authenticate("Bearer invalid"));
        assertThrows(InvalidLoginException.class,
            () -> service((id, sid) -> null).authenticate("Basic valid"));
    }

    private CurrentActorService service(SessionSnapshotReader reader) {
        return new CurrentActorService(verifier, new ValidateSessionService(reader, clock));
    }

    private SessionSnapshotReader.Snapshot snapshot(String status, Instant revoked,
                                                     List<String> roles) {
        return new SessionSnapshotReader.Snapshot(status, NOW.minusSeconds(60), null,
            revoked, NOW.plusSeconds(3600), roles);
    }
}
