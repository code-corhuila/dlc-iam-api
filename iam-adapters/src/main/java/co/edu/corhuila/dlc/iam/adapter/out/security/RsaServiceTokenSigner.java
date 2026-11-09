package co.edu.corhuila.dlc.iam.adapter.out.security;

import co.edu.corhuila.dlc.iam.application.port.out.ServiceTokenSigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** ADR-020: RS256 service JWTs signed with the service key, kept separate from the staff key. */
public final class RsaServiceTokenSigner implements ServiceTokenSigner {
    private final PrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final String kid;
    private final String issuer;
    private final ObjectMapper json;

    public RsaServiceTokenSigner(String privatePem, String publicPem, String kid, String issuer,
                                 ObjectMapper json) {
        if (kid == null || kid.isBlank() || issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("Service JWT key id and issuer are required");
        }
        try {
            var factory = KeyFactory.getInstance("RSA");
            this.privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(pem(privatePem, "PRIVATE KEY")));
            this.publicKey = (RSAPublicKey) factory.generatePublic(
                new X509EncodedKeySpec(pem(publicPem, "PUBLIC KEY")));
            if (publicKey.getModulus().bitLength() < 2048) throw new IllegalArgumentException("RSA key too small");
            byte[] probe = "service-key-check".getBytes(StandardCharsets.US_ASCII);
            var verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(probe);
            if (!verifier.verify(rawSign(probe))) throw new IllegalArgumentException("Service keys do not match");
        } catch (Exception failure) {
            throw new IllegalArgumentException("Invalid service signing key configuration", failure);
        }
        this.kid = kid;
        this.issuer = issuer;
        this.json = json;
    }

    @Override
    public String sign(String subject, String audience, String scope, Instant issuedAt, Instant expiresAt) {
        try {
            String header = b64(json.writeValueAsBytes(Map.of("alg", "RS256", "typ", "JWT", "kid", kid)));
            String claims = b64(json.writeValueAsBytes(Map.of("iss", issuer, "sub", subject, "aud", audience,
                "scope", scope, "iat", issuedAt.getEpochSecond(), "exp", expiresAt.getEpochSecond(),
                "jti", UUID.randomUUID().toString())));
            String input = header + "." + claims;
            return input + "." + b64(rawSign(input.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception failure) {
            throw new IllegalStateException("Service token signing failed", failure);
        }
    }

    public List<Map<String, Object>> publicJwks() {
        return List.of(Map.of("kty", "RSA", "kid", kid, "use", "sig", "alg", "RS256",
            "n", unsigned(publicKey.getModulus()), "e", unsigned(publicKey.getPublicExponent())));
    }

    private byte[] rawSign(byte[] input) throws Exception {
        var signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(input);
        return signer.sign();
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String unsigned(BigInteger number) {
        byte[] bytes = number.toByteArray();
        return b64(bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
    }

    private static byte[] pem(String value, String type) {
        return Base64.getDecoder().decode(value.replace("\\n", "\n").replace("-----BEGIN " + type + "-----", "")
            .replace("-----END " + type + "-----", "").replaceAll("\\s", ""));
    }
}
