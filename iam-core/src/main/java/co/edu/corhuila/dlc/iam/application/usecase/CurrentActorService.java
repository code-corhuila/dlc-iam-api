package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenVerifier;
import java.util.List;
import java.util.UUID;

public final class CurrentActorService {
    private final AccessTokenVerifier tokens;
    private final ValidateSessionService sessions;

    public CurrentActorService(AccessTokenVerifier tokens, ValidateSessionService sessions) {
        this.tokens = tokens;
        this.sessions = sessions;
    }

    public Actor authenticate(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")
            || authorization.length() <= 7 || authorization.length() > 8200) {
            throw new InvalidLoginException();
        }
        try {
            var identity = tokens.verify(authorization.substring(7));
            if (!sessions.active(identity.userId(), identity.sessionId(), identity.roles())) {
                throw new InvalidLoginException();
            }
            return new Actor(identity.userId(), identity.sessionId(), List.copyOf(identity.roles()));
        } catch (IllegalArgumentException rejected) {
            throw new InvalidLoginException();
        }
    }

    public record Actor(UUID userId, UUID sessionId, List<String> roles) { }
}
