package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.adapter.in.http.ServiceTokenController;
import co.edu.corhuila.dlc.iam.adapter.out.security.RsaServiceTokenSigner;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.ServiceClientDirectory;
import co.edu.corhuila.dlc.iam.application.usecase.IssueServiceTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;

/** POST /internal/v1/service-tokens and GET /internal/v1/service-jwks (ADR-020). */
class ServiceTokenControllerTest {
    private static final Instant NOW = Instant.now();
    private final PasswordVerifier verifier = new PasswordVerifier() {
        @Override public boolean matches(String raw, String encoded) {
            return raw.equals(encoded);
        }
        @Override public void dummyCheck(String raw) { }
    };
    private ServiceClientDirectory directory = id -> Optional.of(new ServiceClientDirectory.Client(
        "dlc-worker", true, List.of("s3cret"), Set.of(new ServiceClientDirectory.Grant("billing-api",
            "billing:invoice-pdf:read"))));
    private final RsaServiceTokenSigner signer = signer();
    private final ServiceTokenController controller = new ServiceTokenController(
        new IssueServiceTokenService(id -> directory.find(id), verifier, signer,
            Clock.fixed(NOW, ZoneOffset.UTC)), signer);

    @Test
    void issuesAVerifiableBearerTokenForBasicClientCredentials() throws Exception {
        var response = controller.issue(basic("dlc-worker", "s3cret"),
            Map.<String, Object>of("audience", "billing-api", "scope", "billing:invoice-pdf:read"));
        assertEquals(200, response.getStatusCode().value());
        assertEquals("no-store", response.getHeaders().getCacheControl());
        var body = (Map<?, ?>) response.getBody();
        assertEquals("Bearer", body.get("tokenType"));
        assertEquals(900L, body.get("expiresIn"));
        assertEquals("billing:invoice-pdf:read", body.get("scope"));
        String[] parts = ((String) body.get("accessToken")).split("\\.");
        var claims = new ObjectMapper().readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
        assertEquals("dlc-worker", claims.get("sub"));
        assertEquals("billing-api", claims.get("aud"));
        assertEquals("https://services.test", claims.get("iss"));
        assertEquals(NOW.plusSeconds(900).getEpochSecond(), ((Number) claims.get("exp")).longValue());
        var header = new ObjectMapper().readValue(Base64.getUrlDecoder().decode(parts[0]), Map.class);
        assertEquals("svc-1", header.get("kid"));

        var jwks = (Map<?, ?>) controller.jwks().getBody();
        var key = (Map<?, ?>) ((List<?>) jwks.get("keys")).get(0);
        assertEquals("svc-1", key.get("kid"));
        assertEquals(Set.of("kty", "kid", "use", "alg", "n", "e"), key.keySet());
    }

    @Test
    void mapsFailuresToTheContractStatusesWithoutABody() {
        var request = Map.<String, Object>of("audience", "billing-api", "scope", "billing:invoice-pdf:read");
        assertEquals(401, controller.issue(null, request).getStatusCode().value());
        assertEquals(401, controller.issue("Bearer x", request).getStatusCode().value());
        assertEquals(401, controller.issue("Basic !!!", request).getStatusCode().value());
        var wrong = controller.issue(basic("dlc-worker", "nope"), request);
        assertEquals(401, wrong.getStatusCode().value());
        assertTrue(wrong.getHeaders().getFirst("WWW-Authenticate").startsWith("Basic"));
        assertNull(wrong.getBody());
        assertEquals(403, controller.issue(basic("dlc-worker", "s3cret"),
            Map.<String, Object>of("audience", "patients-api", "scope", "patients:validate")).getStatusCode().value());
        assertEquals(400, controller.issue(basic("dlc-worker", "s3cret"),
            Map.<String, Object>of("audience", "billing-api")).getStatusCode().value());
        assertEquals(400, controller.issue(basic("dlc-worker", "s3cret"),
            Map.<String, Object>of("audience", "billing-api", "scope", "x", "extra", "y")).getStatusCode().value());
        directory = id -> { throw new DataAccessResourceFailureException("down"); };
        assertEquals(503, controller.issue(basic("dlc-worker", "s3cret"), request).getStatusCode().value());
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret)
            .getBytes(StandardCharsets.UTF_8));
    }

    private static RsaServiceTokenSigner signer() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            String priv = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(
                pair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----";
            String pub = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(
                pair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----";
            return new RsaServiceTokenSigner(priv, pub, "svc-1", "https://services.test", new ObjectMapper());
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }
}
