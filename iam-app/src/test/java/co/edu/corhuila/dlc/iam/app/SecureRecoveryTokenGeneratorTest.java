package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import co.edu.corhuila.dlc.iam.adapter.out.security.SecureRecoveryTokenGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class SecureRecoveryTokenGeneratorTest {
    @Test
    void producesIndependentUrlSafe256BitTokens() {
        var generator = new SecureRecoveryTokenGenerator();
        String first = generator.generate();
        String second = generator.generate();
        assertEquals(32, Base64.getUrlDecoder().decode(first).length);
        assertEquals(32, Base64.getUrlDecoder().decode(second).length);
        assertNotEquals(first, second);
    }
}
