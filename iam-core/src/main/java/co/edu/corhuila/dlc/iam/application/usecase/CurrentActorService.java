package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.ActorLookup;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class CurrentActorService {
    private final AccessTokenVerifier tokens;
    private final ActorLookup actors;
    private final Clock clock;

    public CurrentActorService(AccessTokenVerifier tokens, ActorLookup actors, Clock clock) {
        this.tokens = tokens;
        this.actors = actors;
        this.clock = clock;
    }

    public Actor authenticate(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")
            || authorization.length() > 8200) throw new InvalidLoginException();
        try {
            Instant now = clock.instant();
            var identity = tokens.verify(authorization.substring(7), now);
            List<String> roles = actors.activeRoles(identity.userId(), identity.sessionId(),
                now);
            if (roles.isEmpty()) throw new InvalidLoginException();
            return new Actor(identity.userId(), identity.sessionId(), List.copyOf(roles));
        } catch (IllegalArgumentException rejected) {
            throw new InvalidLoginException();
        }
    }

    public record Actor(UUID userId, UUID sessionId, List<String> roles) { }
}
