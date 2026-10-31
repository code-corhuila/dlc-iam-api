package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.security.Sha256ChallengeTokenHasher;
import org.junit.jupiter.api.Test;

class Sha256ChallengeTokenHasherTest {
    private final Sha256ChallengeTokenHasher hasher = new Sha256ChallengeTokenHasher();

    @Test
    void producesStableHexDigestWithoutPersistingRawToken() {
        String digest = hasher.hash("opaque-test-token");
        assertEquals(64, digest.length());
        assertEquals(digest, hasher.hash("opaque-test-token"));
        assertNotEquals(digest, hasher.hash("another-token"));
        assertNotEquals("opaque-test-token", digest);
    }

    @Test
    void rejectsAbsentToken() {
        assertThrows(IllegalArgumentException.class, () -> hasher.hash(null));
        assertThrows(IllegalArgumentException.class, () -> hasher.hash(" "));
    }
}
