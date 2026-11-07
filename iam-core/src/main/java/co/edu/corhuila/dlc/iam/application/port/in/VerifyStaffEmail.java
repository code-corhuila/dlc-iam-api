package co.edu.corhuila.dlc.iam.application.port.in;

import java.util.UUID;

public interface VerifyStaffEmail {
    void verify(String token, UUID correlationId);
}
