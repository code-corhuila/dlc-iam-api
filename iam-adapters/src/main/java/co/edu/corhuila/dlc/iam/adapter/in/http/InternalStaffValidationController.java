package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.out.StaffReader;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * GET /internal/v1/staff/{id}/validation (internal-coordination.yaml): owners such as Appointments check that a
 * staff member is ACTIVE and holds a role, e.g. DENTIST for scheduling. Service JWT with identity:validate; the
 * body carries only staffId, active and roles, never credentials or PII.
 */
@RestController
public class InternalStaffValidationController {
    private static final String SCOPE = "identity:validate";

    private final JwtDecoder serviceTokens;
    private final StaffReader staff;

    public InternalStaffValidationController(@Qualifier("serviceJwtDecoder") JwtDecoder serviceTokens,
                                             StaffReader staff) {
        this.serviceTokens = serviceTokens;
        this.staff = staff;
    }

    @GetMapping("/internal/v1/staff/{id}/validation")
    public ResponseEntity<?> validate(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                                      String authorization, @PathVariable String id) {
        if (authorization == null || !authorization.startsWith("Bearer ") || authorization.length() == 7) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Jwt caller;
        try {
            caller = serviceTokens.decode(authorization.substring(7));
        } catch (JwtException | IllegalArgumentException invalid) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Object scope = caller.getClaims().get("scope");
        Object scopes = caller.getClaims().get("scp");
        boolean permitted = scope instanceof String value && List.of(value.split("\s+")).contains(SCOPE)
            || scopes instanceof List<?> values && values.contains(SCOPE);
        if (!permitted) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        UUID staffId;
        try {
            staffId = UUID.fromString(id);
        } catch (IllegalArgumentException invalid) {
            return ResponseEntity.badRequest().build();
        }
        try {
            var found = staff.find(staffId);
            if (found == null) return ResponseEntity.notFound().build();
            return ResponseEntity.ok(Map.of("staffId", staffId.toString(),
                "active", "ACTIVE".equals(found.status()), "roles", List.copyOf(found.roles())));
        } catch (DataAccessException unavailable) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }
}
