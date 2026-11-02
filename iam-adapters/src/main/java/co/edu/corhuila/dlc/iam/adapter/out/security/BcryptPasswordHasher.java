package co.edu.corhuila.dlc.iam.adapter.out.security;

import co.edu.corhuila.dlc.iam.application.port.out.PasswordHasher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public final class BcryptPasswordHasher implements PasswordHasher {
    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);

    @Override
    public String hash(String rawPassword) {
        return bcrypt.encode(rawPassword);
    }
}
