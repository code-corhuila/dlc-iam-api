package co.edu.corhuila.dlc.iam.application.port.in;

import java.util.UUID;

public interface ResetPassword {
    void reset(String token, String newPassword, UUID correlationId);
}
