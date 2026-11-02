package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.adapter.out.security.BcryptPasswordHasher;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class BcryptPasswordHasherTest {
    @Test
    void hashesWithCostTwelveAndFreshSalt() {
        var hasher = new BcryptPasswordHasher();
        String first = hasher.hash("ValidPass1");
        String second = hasher.hash("ValidPass1");
        assertTrue(first.matches("^\\$2[aby]\\$12\\$.*"));
        assertTrue(new BCryptPasswordEncoder().matches("ValidPass1", first));
        assertNotEquals(first, second);
    }
}
