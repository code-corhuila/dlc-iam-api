package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.ValidateSessionService;
import com.fasterxml.jackson.databind.JsonNode;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InternalSessionValidationController {
    private final JwtDecoder serviceTokens;
    private final JwtDecoder staffTokens;
    private final ValidateSessionService sessions;

    public InternalSessionValidationController(@Qualifier("serviceJwtDecoder") JwtDecoder serviceTokens,
                                               @Qualifier("staffJwtDecoder") JwtDecoder staffTokens,
                                               ValidateSessionService sessions) {
        this.serviceTokens = serviceTokens;
        this.staffTokens = staffTokens;
        this.sessions = sessions;
    }

    @PostMapping("/internal/v1/sessions/validations")
    public ResponseEntity<?> validate(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                                       String authorization, @RequestBody JsonNode body) {
        if (authorization == null || !authorization.startsWith("Bearer ")
            || authorization.length() == 7) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        Jwt caller;
        try {
            caller = serviceTokens.decode(authorization.substring(7));
        } catch (JwtException | IllegalArgumentException invalid) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Object scope = caller.getClaims().get("scope");
        Object scopes = caller.getClaims().get("scp");
        boolean permitted = scope instanceof String value
            && List.of(value.split("\\s+")).contains("identity:validate")
            || scopes instanceof List<?> values && values.contains("identity:validate");
        if (!permitted) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        if (body == null || !body.isObject() || body.size() != 1
            || !body.has("accessToken") || !body.get("accessToken").isTextual()
            || body.get("accessToken").asText().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        try {
            Jwt staff = staffTokens.decode(body.get("accessToken").asText());
            Object roles = staff.getClaims().get("roles");
            if (!(roles instanceof List<?> list) || list.stream().anyMatch(role -> !(role instanceof String))
                || staff.getId() == null || staff.getSubject() == null
                || staff.getClaimAsString("sid") == null
                || staff.getClaims().get("permissions") == null) {
                return ResponseEntity.ok(Map.of("active", false));
            }
            boolean active = sessions.active(UUID.fromString(staff.getSubject()),
                UUID.fromString(staff.getClaimAsString("sid")), list.stream().map(String.class::cast).toList());
            return ResponseEntity.ok(Map.of("active", active));
        } catch (JwtException | IllegalArgumentException invalid) {
            return ResponseEntity.ok(Map.of("active", false));
        } catch (DataAccessException unavailable) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }
}
