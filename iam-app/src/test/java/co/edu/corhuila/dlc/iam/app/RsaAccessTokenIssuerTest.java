package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.out.security.RsaAccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;

class RsaAccessTokenIssuerTest {
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void sessionDecoderVerifiesClaimsSignatureAndPreviousKey() throws Exception {
        KeyPair oldPair = newKeyPair();
        KeyPair currentPair = newKeyPair();
        var oldSigner = new RsaAccessTokenIssuer(
            pem("PRIVATE KEY", oldPair.getPrivate().getEncoded()),
            pem("PUBLIC KEY", oldPair.getPublic().getEncoded()),
            "old", "https://auth.test.invalid", "owner-apis", "[]", json);
        String previous = json.writeValueAsString(oldSigner.publicJwks());
        var currentSigner = new RsaAccessTokenIssuer(
            pem("PRIVATE KEY", currentPair.getPrivate().getEncoded()),
            pem("PUBLIC KEY", currentPair.getPublic().getEncoded()),
            "current", "https://auth.test.invalid", "owner-apis", previous, json);
        var account = new LoginUnitOfWork.StaffAccount(UUID.randomUUID(), "staff@example.test",
            "Staff", "unused", "ACTIVE", Instant.now(), 0, null, 0, List.of("DENTIST"));
        Instant now = Instant.now();
        String token = oldSigner.issue(account, UUID.randomUUID(), now, now.plusSeconds(3600));
        var config = new SessionValidationConfiguration();
        var decoder = config.staffJwtDecoder(currentSigner, "https://auth.test.invalid", "owner-apis");
        assertEquals(account.id().toString(), decoder.decode(token).getSubject());
        var wrongAudience = config.staffJwtDecoder(currentSigner, "https://auth.test.invalid", "other-api");
        assertThrows(JwtException.class, () -> wrongAudience.decode(token));
        assertThrows(JwtException.class, () -> decoder.decode(token + "tampered"));
    }

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
    void issuesOnlyApprovedRolePermissionsForLoginAndRefreshTokens() throws Exception {
        var signer = signer(newKeyPair(), "[]");
        var decoder = new SessionValidationConfiguration().staffJwtDecoder(
            signer, "https://auth.test.invalid", "dilucca-owner-apis");
        Instant now = Instant.now();
        UUID session = UUID.randomUUID();
        assertEquals(List.of("clinical:read", "patients:read", "patients:register", "patients:write"),
            decoder.decode(signer.issue(account(List.of("ADMINISTRATOR")), session,
                now, now.plusSeconds(3600))).getClaimAsStringList("permissions"));
        assertEquals(List.of("patients:read", "patients:register", "patients:write"),
            decoder.decode(signer.issue(account(List.of("SECRETARY_ASSISTANT")), session,
                now, now.plusSeconds(3600))).getClaimAsStringList("permissions"));
        assertEquals(List.of("patients:read"),
            decoder.decode(signer.issue(account(List.of("DENTIST")), session,
                now, now.plusSeconds(3600))).getClaimAsStringList("permissions"));
        assertEquals(List.of("clinical:read", "patients:read", "patients:register", "patients:write"),
            decoder.decode(signer.issue(account(List.of("DENTIST", "ADMINISTRATOR")), session,
                now, now.plusSeconds(3600))).getClaimAsStringList("permissions"));
        var refreshed = decoder.decode(signer.issue(account(List.of("ADMINISTRATOR")), session,
            now.plusSeconds(60), now.plusSeconds(3660))).getClaimAsStringList("permissions");
        assertEquals(List.of("clinical:read", "patients:read", "patients:register", "patients:write"),
            refreshed);
        assertFalse(refreshed.contains("clinical:write"));
        assertThrows(IllegalStateException.class, () -> signer.issue(account(List.of("PATIENT")),
            session, now, now.plusSeconds(3600)));
    }

    private static LoginUnitOfWork.StaffAccount account(List<String> roles) {
        return new LoginUnitOfWork.StaffAccount(UUID.randomUUID(), "staff@example.test",
            "Staff", "unused", "ACTIVE", Instant.now(), 0, null, 0, roles);
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
