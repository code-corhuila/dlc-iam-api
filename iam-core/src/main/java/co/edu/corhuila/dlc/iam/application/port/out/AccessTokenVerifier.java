package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;

public interface AccessTokenVerifier {
    VerifiedAccessToken verify(String token, Instant now);

    record VerifiedAccessToken(UUID userId, UUID sessionId) { }
}
