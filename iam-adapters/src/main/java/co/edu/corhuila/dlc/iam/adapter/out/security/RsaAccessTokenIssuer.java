package co.edu.corhuila.dlc.iam.adapter.out.security;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public final class RsaAccessTokenIssuer implements AccessTokenIssuer, AccessTokenVerifier {
    private final PrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final String kid;
    private final String issuer;
    private final String audience;
    private final ObjectMapper json;
    private final List<Map<String, Object>> jwks;

    public RsaAccessTokenIssuer(@Value("${IAM_JWT_PRIVATE_KEY_PEM}") String privatePem,
                                @Value("${IAM_JWT_PUBLIC_KEY_PEM}") String publicPem,
                                @Value("${IAM_JWT_KID}") String kid,
                                @Value("${IAM_JWT_ISSUER}") String issuer,
                                @Value("${IAM_JWT_AUDIENCE}") String audience,
                                @Value("${IAM_JWT_PREVIOUS_JWKS_JSON:[]}") String previousJwksJson,
                                ObjectMapper json) {
        try {
            var factory = KeyFactory.getInstance("RSA");
            this.privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(
                decodePem(privatePem, "PRIVATE KEY")));
            PublicKey parsedPublic = factory.generatePublic(new X509EncodedKeySpec(
                decodePem(publicPem, "PUBLIC KEY")));
            this.publicKey = (RSAPublicKey) parsedPublic;
            if (this.publicKey.getModulus().bitLength() < 2048) {
                throw new IllegalArgumentException("RSA signing key must have at least 2048 bits");
            }
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(this.privateKey);
            signer.update("key-pair-check".getBytes(StandardCharsets.US_ASCII));
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(this.publicKey);
            verifier.update("key-pair-check".getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(signer.sign())) {
                throw new IllegalArgumentException("RSA public and private keys do not match");
            }
        } catch (Exception failure) {
            throw new IllegalArgumentException("Invalid RSA signing key configuration", failure);
        }
        if (kid.isBlank() || issuer.isBlank() || audience.isBlank()) {
            throw new IllegalArgumentException("JWT key id, issuer and audience are required");
        }
        this.kid = kid;
        this.issuer = issuer;
        this.audience = audience;
        this.json = json;
        this.jwks = loadVerificationKeys(previousJwksJson);
    }

    @Override
    public String issue(LoginUnitOfWork.StaffAccount staff, UUID sessionId,
                        Instant issuedAt, Instant expiresAt) {
        try {
            String header = encodeJson(Map.of("alg", "RS256", "typ", "JWT", "kid", kid));
            String claims = encodeJson(Map.of(
                "sub", staff.id().toString(), "iss", issuer, "aud", audience,
                "iat", issuedAt.getEpochSecond(), "exp", expiresAt.getEpochSecond(),
                "jti", UUID.randomUUID().toString(), "sid", sessionId.toString(),
                "roles", staff.roles(), "permissions", List.of()));
            String signingInput = header + "." + claims;
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signature.sign());
        } catch (Exception failure) {
            throw new IllegalStateException("Access token signing failed", failure);
        }
    }

    public List<Map<String, Object>> publicJwks() {
        return jwks;
    }

    @Override
    public VerifiedAccessToken verify(String token, Instant now) {
        if (token == null || token.length() > 8192 || now == null) {
            throw new IllegalArgumentException("Invalid access token");
        }
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) throw new IllegalArgumentException();
            JsonNode header = json.readTree(Base64.getUrlDecoder().decode(parts[0]));
            if (!"RS256".equals(header.path("alg").asText())
                || !"JWT".equals(header.path("typ").asText())) {
                throw new IllegalArgumentException();
            }
            String tokenKid = header.path("kid").asText();
            Map<String, Object> jwk = jwks.stream()
                .filter(key -> tokenKid.equals(key.get("kid"))).findFirst()
                .orElseThrow(IllegalArgumentException::new);
            RSAPublicKey key = verificationKey(jwk);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(key);
            signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!signature.verify(Base64.getUrlDecoder().decode(parts[2]))) {
                throw new IllegalArgumentException();
            }
            JsonNode claims = json.readTree(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode issued = claims.path("iat");
            JsonNode expiry = claims.path("exp");
            if (!issuer.equals(claims.path("iss").asText())
                || !audience.equals(claims.path("aud").asText())
                || !issued.isIntegralNumber() || !expiry.isIntegralNumber()
                || issued.asLong() > now.getEpochSecond()
                || expiry.asLong() <= now.getEpochSecond()
                || expiry.asLong() > issued.asLong() + 3600) {
                throw new IllegalArgumentException();
            }
            return new VerifiedAccessToken(UUID.fromString(claims.path("sub").asText()),
                UUID.fromString(claims.path("sid").asText()));
        } catch (Exception rejected) {
            throw new IllegalArgumentException("Invalid access token");
        }
    }

    private static RSAPublicKey verificationKey(Map<String, Object> jwk)
        throws GeneralSecurityException {
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
            new RSAPublicKeySpec(
                new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("n"))),
                new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("e")))));
    }

    private List<Map<String, Object>> loadVerificationKeys(String previousJson) {
        Map<String, Object> current = Map.of(
            "kty", "RSA", "kid", kid, "use", "sig", "alg", "RS256",
            "n", unsigned(publicKey.getModulus()),
            "e", unsigned(publicKey.getPublicExponent()));
        try {
            List<Map<String, Object>> previous = json.readValue(previousJson,
                new TypeReference<>() { });
            if (previous.size() > 5) {
                throw new IllegalArgumentException("Too many previous verification keys");
            }
            var all = new java.util.ArrayList<Map<String, Object>>();
            all.add(current);
            var seen = new java.util.HashSet<String>();
            seen.add(kid);
            for (Map<String, Object> candidate : previous) {
                if (!candidate.keySet().equals(Set.of("kty", "kid", "use", "alg", "n", "e"))
                    || !"RSA".equals(candidate.get("kty"))
                    || !"sig".equals(candidate.get("use"))
                    || !"RS256".equals(candidate.get("alg"))
                    || !(candidate.get("kid") instanceof String oldKid)
                    || oldKid.isBlank() || !seen.add(oldKid)
                    || !(candidate.get("n") instanceof String modulus)
                    || !(candidate.get("e") instanceof String exponent)) {
                    throw new IllegalArgumentException("Invalid previous public JWK");
                }
                var key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(new BigInteger(1, Base64.getUrlDecoder().decode(modulus)),
                        new BigInteger(1, Base64.getUrlDecoder().decode(exponent))));
                if (key.getModulus().bitLength() < 2048) {
                    throw new IllegalArgumentException("Previous RSA key is too small");
                }
                all.add(Map.copyOf(candidate));
            }
            return List.copyOf(all);
        } catch (Exception failure) {
            throw new IllegalArgumentException("Invalid previous public JWK configuration", failure);
        }
    }

    private String encodeJson(Map<String, ?> value) throws JsonProcessingException {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json
            .writeValueAsBytes(value));
    }

    private static String unsigned(BigInteger number) {
        byte[] bytes = number.toByteArray();
        int offset = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            java.util.Arrays.copyOfRange(bytes, offset, bytes.length));
    }

    private static byte[] decodePem(String value, String type) {
        String normalized = value.replace("\\n", "\n");
        String body = normalized.replace("-----BEGIN " + type + "-----", "")
            .replace("-----END " + type + "-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }
}
