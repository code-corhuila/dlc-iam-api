package co.edu.corhuila.dlc.iam.application.port.out;

import java.util.List;
import java.util.UUID;

public interface AccessTokenVerifier {
    VerifiedAccessToken verify(String token);

    record VerifiedAccessToken(UUID userId, UUID sessionId, List<String> roles) { }
}
