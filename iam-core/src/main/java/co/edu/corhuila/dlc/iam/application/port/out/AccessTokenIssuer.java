package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.UUID;

public interface AccessTokenIssuer {
    String issue(LoginUnitOfWork.StaffAccount staff, UUID sessionId,
                 Instant issuedAt, Instant expiresAt);
}
