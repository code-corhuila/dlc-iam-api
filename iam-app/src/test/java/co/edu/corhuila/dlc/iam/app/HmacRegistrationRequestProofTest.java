package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.security.HmacRegistrationRequestProof;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class HmacRegistrationRequestProofTest {
    @Test
    void isDeterministicAndBindsEveryFieldWithoutPersistingTheRequest() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);
        var proof = new HmacRegistrationRequestProof(key);
        byte[] original = proof.prove("ada@example.test", "Password1", "Ada", "DENTIST");
        assertArrayEquals(original, proof.prove("ada@example.test", "Password1", "Ada", "DENTIST"));
        assertFalse(Arrays.equals(original, proof.prove("eve@example.test", "Password1", "Ada", "DENTIST")));
        assertFalse(Arrays.equals(original, proof.prove("ada@example.test", "Password2", "Ada", "DENTIST")));
        assertFalse(Arrays.equals(original, proof.prove("ada@example.test", "Password1", "Eva", "DENTIST")));
        assertFalse(Arrays.equals(original, proof.prove("ada@example.test", "Password1", "Ada", "SECRETARY_ASSISTANT")));
        key[0] = 0;
        assertArrayEquals(original, proof.prove("ada@example.test", "Password1", "Ada", "DENTIST"));
    }

    @Test
    void rejectsWeakKeysAndMissingFields() {
        assertThrows(IllegalArgumentException.class, () -> new HmacRegistrationRequestProof(new byte[31]));
        var proof = new HmacRegistrationRequestProof(new byte[32]);
        assertThrows(IllegalArgumentException.class, () -> proof.prove(null, "Password1", "Ada", "DENTIST"));
    }
}
