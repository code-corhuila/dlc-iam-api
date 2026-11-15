package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.ServiceClientDirectory;
import co.edu.corhuila.dlc.iam.application.port.out.ServiceTokenSigner;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** ADR-020: IAM issues 15-minute service JWTs by client credentials, only for granted audience and scopes. */
class IssueServiceTokenServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-08T12:00:00Z");
    private final List<String> signed = new ArrayList<>();
    private final List<String> dummyChecks = new ArrayList<>();
    private Optional<ServiceClientDirectory.Client> client = Optional.of(new ServiceClientDirectory.Client(
        "clinical-api", true, List.of("hash-old", "hash-new"),
        Set.of(new ServiceClientDirectory.Grant("patients-api", "patients:validate"),
            new ServiceClientDirectory.Grant("appointments-api", "assignments:read"),
            new ServiceClientDirectory.Grant("appointments-api", "patient-gates:coordinate"))));

    private final PasswordVerifier verifier = new PasswordVerifier() {
        @Override public boolean matches(String raw, String encoded) {
            return ("secret-" + encoded).equals(raw);
        }
        @Override public void dummyCheck(String raw) {
            dummyChecks.add(raw);
        }
    };
    private final ServiceTokenSigner signer = (sub, aud, scope, iat, exp) -> {
        String token = sub + "|" + aud + "|" + scope + "|" + iat.getEpochSecond() + "|" + exp.getEpochSecond();
        signed.add(token);
        return token;
    };
    private final IssueServiceTokenService service = new IssueServiceTokenService(
        id -> client.filter(found -> found.clientId().equals(id)), verifier, signer,
        Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void issuesAFifteenMinuteTokenForGrantedScopesWithEitherActiveSecret() {
        var issued = service.issue("clinical-api", "secret-hash-new", "appointments-api",
            "patient-gates:coordinate  assignments:read");
        assertEquals("clinical-api|appointments-api|assignments:read patient-gates:coordinate|"
            + NOW.getEpochSecond() + "|" + NOW.plusSeconds(900).getEpochSecond(), issued.accessToken());
        assertEquals(900, issued.expiresIn());
        assertEquals("assignments:read patient-gates:coordinate", issued.scope());

        assertEquals("patients:validate",
            service.issue("clinical-api", "secret-hash-old", "patients-api", "patients:validate").scope());
    }

    @Test
    void unknownDisabledOrWrongSecretClientsAreInvalidWithoutSigning() {
        assertThrows(IssueServiceTokenService.InvalidClientException.class,
            () -> service.issue("clinical-api", "wrong", "patients-api", "patients:validate"));
        assertThrows(IssueServiceTokenService.InvalidClientException.class,
            () -> service.issue("unknown-api", "secret-hash-new", "patients-api", "patients:validate"));
        assertEquals(List.of("secret-hash-new"), dummyChecks, "unknown clients still pay a hash check");

        client = client.map(found -> new ServiceClientDirectory.Client(found.clientId(), false,
            found.secretHashes(), found.grants()));
        assertThrows(IssueServiceTokenService.InvalidClientException.class,
            () -> service.issue("clinical-api", "secret-hash-new", "patients-api", "patients:validate"));
        assertTrue(signed.isEmpty());
    }

    @Test
    void anyUngrantedAudienceOrScopeIsForbiddenWithoutSigning() {
        assertThrows(IssueServiceTokenService.ScopeNotGrantedException.class,
            () -> service.issue("clinical-api", "secret-hash-new", "billing-api", "patients:validate"));
        assertThrows(IssueServiceTokenService.ScopeNotGrantedException.class,
            () -> service.issue("clinical-api", "secret-hash-new", "appointments-api",
                "assignments:read billing:encounter-freeze:write"));
        assertTrue(signed.isEmpty());
    }

    @Test
    void malformedRequestsAreRejectedBeforeReadingTheClient() {
        for (String[] bad : new String[][] {
            {null, "s", "patients-api", "patients:validate"},
            {"clinical-api", null, "patients-api", "patients:validate"},
            {"clinical-api", "s", " ", "patients:validate"},
            {"clinical-api", "s", "patients-api", ""},
            {"clinical-api", "s", "Patients API", "patients:validate"}}) {
            assertThrows(IllegalArgumentException.class, () -> service.issue(bad[0], bad[1], bad[2], bad[3]));
        }
        assertTrue(dummyChecks.isEmpty());
    }
}
