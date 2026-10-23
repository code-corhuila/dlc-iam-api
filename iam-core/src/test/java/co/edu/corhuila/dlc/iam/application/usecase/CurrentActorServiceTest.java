package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.ActorLookup;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CurrentActorServiceTest {
    private final UUID user = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();
    private final Clock clock = Clock.fixed(Instant.parse("2026-10-23T12:00:00Z"),
        ZoneOffset.UTC);
    private final AccessTokenVerifier verifier = (token, now) -> {
        if (!"valid".equals(token)) throw new IllegalArgumentException();
        return new AccessTokenVerifier.VerifiedAccessToken(user, session);
    };

    @Test
    void usesCurrentDatabaseRolesForEligibleSession() {
        ActorLookup lookup = (id, sid, now) -> {
            assertEquals(user, id);
            assertEquals(session, sid);
            assertEquals(clock.instant(), now);
            return List.of("ADMINISTRATOR");
        };
        var actor = new CurrentActorService(verifier, lookup, clock)
            .authenticate("Bearer valid");
        assertEquals(List.of("ADMINISTRATOR"), actor.roles());
    }

    @Test
    void rejectsInvalidTokenAndIneligibleSession() {
        var service = new CurrentActorService(verifier,
            (id, sid, now) -> List.of(), clock);
        assertThrows(InvalidLoginException.class,
            () -> service.authenticate("Bearer invalid"));
        assertThrows(InvalidLoginException.class,
            () -> service.authenticate("Bearer valid"));
        assertThrows(InvalidLoginException.class,
            () -> service.authenticate("Basic valid"));
    }
}
