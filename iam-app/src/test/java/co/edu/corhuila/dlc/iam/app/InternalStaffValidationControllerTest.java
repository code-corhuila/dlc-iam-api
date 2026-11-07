package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import co.edu.corhuila.dlc.iam.adapter.in.http.InternalStaffValidationController;
import co.edu.corhuila.dlc.iam.application.port.out.StaffReader;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/** GET /internal/v1/staff/{id}/validation: active state and current roles, no credentials or PII. */
class InternalStaffValidationControllerTest {
    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");
    private static final UUID ID = UUID.randomUUID();
    private final JwtDecoder service = mock(JwtDecoder.class);
    private final StaffReader reader = mock(StaffReader.class);
    private final InternalStaffValidationController controller =
        new InternalStaffValidationController(service, reader);

    @Test
    void returnsOnlyIdActiveStateAndRolesForAServiceWithTheScope() {
        allow("caller");
        when(reader.find(ID)).thenReturn(staff("ACTIVE", List.of("DENTIST")));
        assertEquals(Map.of("staffId", ID.toString(), "active", true, "roles", List.of("DENTIST")),
            controller.validate("Bearer caller", ID.toString()).getBody());

        when(reader.find(ID)).thenReturn(staff("DISABLED", List.of("DENTIST")));
        assertEquals(false, ((Map<?, ?>) controller.validate("Bearer caller", ID.toString()).getBody()).get("active"));
    }

    @Test
    void rejectsCallersWithoutAValidServiceTokenOrScopeBeforeReading() {
        when(service.decode("other")).thenReturn(jwt("other", "patients:validate"));
        assertEquals(401, controller.validate(null, ID.toString()).getStatusCode().value());
        assertEquals(403, controller.validate("Bearer other", ID.toString()).getStatusCode().value());
        verifyNoInteractions(reader);
    }

    @Test
    void unknownIdIsNotFoundInvalidIdIsBadRequestAndOutageIsUnavailable() {
        allow("caller");
        assertEquals(404, controller.validate("Bearer caller", ID.toString()).getStatusCode().value());
        assertEquals(400, controller.validate("Bearer caller", "not-a-uuid").getStatusCode().value());
        when(reader.find(ID)).thenThrow(new DataAccessResourceFailureException("down"));
        assertEquals(503, controller.validate("Bearer caller", ID.toString()).getStatusCode().value());
    }

    private void allow(String token) {
        when(service.decode(token)).thenReturn(jwt(token, "identity:validate"));
    }

    private static StaffReader.Staff staff(String status, List<String> roles) {
        return new StaffReader.Staff(ID, "ana@example.test", "Ana", roles, status, NOW, NOW, 1);
    }

    private static Jwt jwt(String token, String scope) {
        return Jwt.withTokenValue(token).header("alg", "RS256").issuedAt(NOW.minusSeconds(60))
            .expiresAt(NOW.plusSeconds(3600)).claim("scope", scope).build();
    }
}
