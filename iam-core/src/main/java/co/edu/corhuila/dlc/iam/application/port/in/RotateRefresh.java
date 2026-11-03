package co.edu.corhuila.dlc.iam.application.port.in;

import java.util.List;
import java.util.UUID;

public interface RotateRefresh {
    Result rotate(String rawRefresh, UUID correlationId);

    record Result(String accessToken, String refreshToken, Staff user) { }
    record Staff(UUID id, String email, String name, List<String> roles,
                 String status, long version) { }
}
