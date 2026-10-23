package co.edu.corhuila.dlc.iam.application.port.in;

import java.util.List;
import java.util.UUID;

public interface LoginUseCase {
    LoginResult login(String email, String password, UUID correlationId, String peerIp);

    record Staff(UUID id, String email, String name, List<String> roles,
                 String status, long version) { }

    record LoginResult(String accessToken, String refreshToken, Staff user) { }
}
