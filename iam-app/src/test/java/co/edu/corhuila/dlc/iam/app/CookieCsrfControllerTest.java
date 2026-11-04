package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import co.edu.corhuila.dlc.iam.adapter.in.http.CookieCsrfController;
import co.edu.corhuila.dlc.iam.adapter.in.http.CookieOriginPolicy;
import co.edu.corhuila.dlc.iam.application.port.out.LogoutUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.usecase.CookieCsrfProofService;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class CookieCsrfControllerTest {
    @Test
    void onlyApprovedOriginAndEligibleCookieReceiveNonCacheableProof() {
        var controller = new CookieCsrfController(proofs(),
            new CookieOriginPolicy("https://portal.example.test"));
        assertEquals(403, controller.read("cookie", "https://evil.example", "same-site")
            .getStatusCode().value());
        assertEquals(403, controller.read("cookie", "https://portal.example.test", "cross-site")
            .getStatusCode().value());
        assertEquals(401, controller.read(null, "https://portal.example.test", "same-site")
            .getStatusCode().value());
        var result = controller.read("cookie", "https://portal.example.test", "same-site");
        assertEquals(200, result.getStatusCode().value());
        assertEquals("no-store", result.getHeaders().getCacheControl());
        assertNotNull(((Map<?, ?>) result.getBody()).get("csrfToken"));
    }

    private static CookieCsrfProofService proofs() {
        LogoutUnitOfWork store = new LogoutUnitOfWork() {
            public <T> T execute(Function<Store, T> operation) {
                return operation.apply(new Store() {
                    public Credential findForUpdate(String hash) {
                        return hash.equals("hash:cookie") ? new Credential(UUID.randomUUID(),
                            UUID.randomUUID(), Instant.now().plusSeconds(60), null, null,
                            null, null, Instant.now().plusSeconds(60)) : null;
                    }
                    public List<UUID> activeSessionsForUpdate(UUID user, UUID current,
                                                              boolean all) { throw new AssertionError(); }
                    public boolean revokeSession(UUID user, UUID id, Instant at) {
                        throw new AssertionError();
                    }
                    public void appendSessionRevoked(UUID event, UUID user, UUID id,
                                                     UUID correlation, Instant at) {
                        throw new AssertionError();
                    }
                });
            }
        };
        RefreshCredential hash = new RefreshCredential() {
            public String generate() { return "unused"; }
            public String hash(String raw) { return "hash:" + raw; }
        };
        return new CookieCsrfProofService(store, hash, new byte[32], Clock.systemUTC(),
            new SecureRandom());
    }
}
