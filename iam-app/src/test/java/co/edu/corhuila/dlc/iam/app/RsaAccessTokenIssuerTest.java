package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.security.RsaAccessTokenIssuer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RsaAccessTokenIssuerTest {
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void rolloverPublishesCurrentAndPreviousPublicKeysOnly() throws Exception {
        KeyPair current = newKeyPair();
        KeyPair previous = newKeyPair();
        var oldPublic = (RSAPublicKey) previous.getPublic();
        String oldJson = json.writeValueAsString(List.of(Map.of(
            "kty", "RSA", "kid", "previous", "use", "sig", "alg", "RS256",
            "n", unsigned(oldPublic.getModulus().toByteArray()),
            "e", unsigned(oldPublic.getPublicExponent().toByteArray()))));

        var signer = signer(current, oldJson);
        assertEquals(2, signer.publicJwks().size());
        assertEquals("current", signer.publicJwks().getFirst().get("kid"));
        assertEquals("previous", signer.publicJwks().get(1).get("kid"));
        assertFalse(signer.publicJwks().get(1).containsKey("d"));

        String leaked = oldJson.replace("\"kid\":\"previous\"",
            "\"kid\":\"previous\",\"d\":\"private\"");
        assertThrows(IllegalArgumentException.class, () -> signer(current, leaked));
    }

    @Test
    void mismatchedKeysStopStartup() throws Exception {
        KeyPair first = newKeyPair();
        KeyPair other = newKeyPair();
        assertThrows(IllegalArgumentException.class, () -> new RsaAccessTokenIssuer(
            pem("PRIVATE KEY", first.getPrivate().getEncoded()),
            pem("PUBLIC KEY", other.getPublic().getEncoded()),
            "current", "https://auth.test.invalid", "dilucca-owner-apis", "[]", json));
    }

    private RsaAccessTokenIssuer signer(KeyPair pair, String previousJson) {
        return new RsaAccessTokenIssuer(
            pem("PRIVATE KEY", pair.getPrivate().getEncoded()),
            pem("PUBLIC KEY", pair.getPublic().getEncoded()),
            "current", "https://auth.test.invalid", "dilucca-owner-apis",
            previousJson, json);
    }

    private static KeyPair newKeyPair() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String pem(String type, byte[] data) {
        return "-----BEGIN " + type + "-----\n"
            + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(data)
            + "\n-----END " + type + "-----";
    }

    private static String unsigned(byte[] bytes) {
        int offset = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            Arrays.copyOfRange(bytes, offset, bytes.length));
    }
}
