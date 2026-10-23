package co.edu.corhuila.dlc.iam.adapter.out.security;

import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public final class BcryptPasswordVerifier implements PasswordVerifier {
    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);
    private final String dummyHash = bcrypt.encode("unused-dummy-credential");

    @Override
    public boolean matches(String raw, String encoded) {
        return bcrypt.matches(raw, encoded);
    }

    @Override
    public void dummyCheck(String raw) {
        bcrypt.matches(raw, dummyHash);
    }
}
