package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.in.ReplaceRoleAssignments;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class RoleAssignmentController {
    private static final Set<String> ASSIGNABLE = Set.of("DENTIST", "SECRETARY_ASSISTANT");
    private final CurrentActorService actors;
    private final ReplaceRoleAssignments assignments;
    private final ObjectMapper json;

    public RoleAssignmentController(CurrentActorService actors,
                                    ReplaceRoleAssignments assignments, ObjectMapper json) {
        this.actors = actors;
        this.assignments = assignments;
        this.json = json;
    }

    @PutMapping("/api/v1/auth/staff/{id}/role-assignments")
    public ResponseEntity<?> replace(@PathVariable String id,
                                     @RequestHeader(value = HttpHeaders.AUTHORIZATION,
                                                    required = false) String authorization,
                                     @RequestBody(required = false) String rawBody) {
        UUID correlationId = UUID.randomUUID();
        try {
            var actor = actors.authenticate(authorization);
            if (!actor.roles().contains("ADMINISTRATOR")) {
                return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
            }
            UUID staffId;
            JsonNode body;
            try {
                staffId = UUID.fromString(id);
                body = rawBody == null ? null : json.readTree(rawBody);
            } catch (IllegalArgumentException | JsonProcessingException invalid) {
                return invalid(correlationId);
            }
            if (body == null || !body.isObject() || body.size() != 3
                || !body.has("roles") || !body.get("roles").isArray()
                || body.get("roles").isEmpty() || body.get("roles").size() > ASSIGNABLE.size()
                || !body.has("expectedVersion") || !body.get("expectedVersion").isIntegralNumber()
                || !body.get("expectedVersion").canConvertToLong()
                || body.get("expectedVersion").asLong() < 1
                || !body.has("reason") || !body.get("reason").isTextual()) {
                return invalid(correlationId);
            }
            List<String> roles = new ArrayList<>();
            for (JsonNode role : body.get("roles")) {
                if (!role.isTextual() || !ASSIGNABLE.contains(role.asText())
                    || roles.contains(role.asText())) {
                    return invalid(correlationId);
                }
                roles.add(role.asText());
            }
            String reason = body.get("reason").asText();
            if (reason.isBlank() || !reason.equals(reason.strip()) || reason.length() > 1000) {
                return invalid(correlationId);
            }
            var result = assignments.replace(actor.userId(), staffId, roles,
                body.get("expectedVersion").asLong(), reason, correlationId);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString()).body(result);
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication required",
                correlationId);
        } catch (SecurityException forbidden) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
        } catch (NoSuchElementException missing) {
            return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Staff not found", correlationId);
        } catch (ConcurrentModificationException conflict) {
            return error(HttpStatus.CONFLICT, "CONFLICT", "Staff version changed", correlationId);
        } catch (IllegalArgumentException invalid) {
            return invalid(correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Role assignment is temporarily unavailable", correlationId);
        }
    }

    private static ResponseEntity<Map<String, String>> invalid(UUID correlationId) {
        return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
            "Invalid role assignment request", correlationId);
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
                                                              String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message,
                "traceId", correlationId.toString()));
    }
}
