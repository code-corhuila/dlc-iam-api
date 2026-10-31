package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import co.edu.corhuila.dlc.iam.adapter.in.http.InternalSessionValidationController;
import co.edu.corhuila.dlc.iam.application.port.out.SessionSnapshotReader;
import co.edu.corhuila.dlc.iam.application.usecase.ValidateSessionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

class InternalSessionValidationControllerTest {
    private static final Instant NOW = Instant.parse("2026-10-29T12:00:00Z");
    private static final UUID USER = UUID.randomUUID();
    private static final UUID SESSION = UUID.randomUUID();
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void checksServiceScopeAndCurrentOwnerState() throws Exception {
        var service = mock(JwtDecoder.class);
        var staff = mock(JwtDecoder.class);
        when(service.decode("caller")).thenReturn(jwt("caller", Map.of("scope", "identity:validate")));
        when(service.decode("without-scope")).thenReturn(jwt("without-scope", Map.of("scope", "other:read")));
        when(staff.decode("staff")).thenReturn(jwt("staff", Map.of(
            "sub", USER.toString(), "sid", SESSION.toString(), "roles", List.of("DENTIST"),
            "permissions", List.of(), "jti", "token-1")));
        var eligible = snapshot(null, List.of("DENTIST"));
        var controller = controller(service, staff, (user, session) -> eligible);
        var body = json.readTree("{\"accessToken\":\"staff\"}");

        assertEquals(Map.of("active", true), controller.validate("Bearer caller", body).getBody());
        assertEquals(403, controller.validate("Bearer without-scope", body).getStatusCode().value());
        assertEquals(401, controller.validate(null, body).getStatusCode().value());
        assertEquals(400, controller.validate("Bearer caller", json.readTree(
            "{\"accessToken\":\"staff\",\"extra\":1}")).getStatusCode().value());

        var revoked = controller(service, staff, (user, session) -> snapshot(NOW, List.of("DENTIST")));
        assertEquals(Map.of("active", false), revoked.validate("Bearer caller", body).getBody());
        var changedRoles = controller(service, staff, (user, session) -> snapshot(null, List.of("ADMINISTRATOR")));
        assertEquals(Map.of("active", false), changedRoles.validate("Bearer caller", body).getBody());
    }

    @Test
    void invalidStaffTokenIsInactiveAndDatabaseFailureIsUnavailable() throws Exception {
        var service = mock(JwtDecoder.class);
        var staff = mock(JwtDecoder.class);
        when(service.decode("caller")).thenReturn(jwt("caller", Map.of("scope", "identity:validate")));
        when(staff.decode("bad")).thenThrow(new JwtException("invalid"));
        when(staff.decode("staff")).thenReturn(jwt("staff", Map.of(
            "sub", USER.toString(), "sid", SESSION.toString(), "roles", List.of("DENTIST"),
            "permissions", List.of(), "jti", "token-1")));
        var reader = (SessionSnapshotReader) (user, session) -> {
            throw new DataAccessResourceFailureException("unavailable");
        };
        var controller = controller(service, staff, reader);
        assertEquals(Map.of("active", false), controller.validate("Bearer caller",
            json.readTree("{\"accessToken\":\"bad\"}")).getBody());
        assertEquals(503, controller.validate("Bearer caller",
            json.readTree("{\"accessToken\":\"staff\"}")).getStatusCode().value());
    }

    private InternalSessionValidationController controller(JwtDecoder service, JwtDecoder staff,
                                                            SessionSnapshotReader reader) {
        return new InternalSessionValidationController(service, staff,
            new ValidateSessionService(reader, Clock.fixed(NOW, ZoneOffset.UTC)));
    }

    private SessionSnapshotReader.Snapshot snapshot(Instant revoked, List<String> roles) {
        return new SessionSnapshotReader.Snapshot("ACTIVE", NOW.minusSeconds(60), null,
            revoked, NOW.plusSeconds(3600), roles);
    }

    private Jwt jwt(String token, Map<String, Object> claims) {
        var builder = Jwt.withTokenValue(token).header("alg", "RS256")
            .issuedAt(NOW.minusSeconds(60)).expiresAt(NOW.plusSeconds(3600));
        claims.forEach(builder::claim);
        return builder.build();
    }
}
