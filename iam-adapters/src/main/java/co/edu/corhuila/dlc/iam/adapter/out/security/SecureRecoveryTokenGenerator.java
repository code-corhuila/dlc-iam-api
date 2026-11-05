package co.edu.corhuila.dlc.iam.adapter.out.security;

import co.edu.corhuila.dlc.iam.application.port.out.RecoveryTokenGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Component;

@Component
public final class SecureRecoveryTokenGenerator implements RecoveryTokenGenerator {
    private final SecureRandom random = new SecureRandom();

    @Override
    public String generate() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
