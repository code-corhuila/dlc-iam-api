package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.security.RsaAccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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

    @Test
    void verifiesSignedCurrentAndRolloverTokens() throws Exception {
        KeyPair old = newKeyPair();
        KeyPair current = newKeyPair();
        Instant now = Instant.parse("2026-10-23T12:00:00Z");
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        var staff = new LoginUnitOfWork.StaffAccount(userId, "admin@example.test",
            "Admin", "hash", "ACTIVE", now, 0, null, 1,
            List.of("ADMINISTRATOR"));
        String oldToken = signer(old, "[]").issue(staff, sessionId, now, now.plusSeconds(3600));
        var oldPublic = (RSAPublicKey) old.getPublic();
        String oldJwk = json.writeValueAsString(List.of(Map.of(
            "kty", "RSA", "kid", "current", "use", "sig", "alg", "RS256",
            "n", unsigned(oldPublic.getModulus().toByteArray()),
            "e", unsigned(oldPublic.getPublicExponent().toByteArray()))));
        // The old signing kid must differ from the new signing kid.
        var rotated = new RsaAccessTokenIssuer(
            pem("PRIVATE KEY", current.getPrivate().getEncoded()),
            pem("PUBLIC KEY", current.getPublic().getEncoded()),
            "rotated", "https://auth.test.invalid", "dilucca-owner-apis", oldJwk, json);
        assertEquals(new AccessTokenVerifier.VerifiedAccessToken(userId, sessionId),
            rotated.verify(oldToken, now));
        String newToken = rotated.issue(staff, sessionId, now, now.plusSeconds(3600));
        assertEquals(userId, rotated.verify(newToken, now).userId());
        assertThrows(IllegalArgumentException.class,
            () -> rotated.verify(newToken, now.plusSeconds(3600)));
        assertThrows(IllegalArgumentException.class,
            () -> rotated.verify(newToken.substring(0, newToken.length() - 2) + "ab", now));
        assertThrows(IllegalArgumentException.class,
            () -> signer(newKeyPair(), "[]").verify(newToken, now));
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
