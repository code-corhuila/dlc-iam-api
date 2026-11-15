package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.UpdateStaffNameService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ConcurrentModificationException;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class StaffNameController {
    private final CurrentActorService actors;
    private final UpdateStaffNameService names;
    private final ObjectMapper json;

    public StaffNameController(CurrentActorService actors, UpdateStaffNameService names,
                               ObjectMapper json) {
        this.actors = actors;
        this.names = names;
        this.json = json;
    }

    @PatchMapping("/api/v1/auth/staff/{id}")
    public ResponseEntity<?> update(@PathVariable String id,
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
            if (body == null || !body.isObject() || body.size() != 2
                || !body.has("name") || !body.get("name").isTextual()
                || !body.has("expectedVersion") || !body.get("expectedVersion").isIntegralNumber()
                || !body.get("expectedVersion").canConvertToLong()) {
                return invalid(correlationId);
            }
            var result = names.update(actor.userId(), staffId, body.get("name").asText(),
                body.get("expectedVersion").asLong(), correlationId);
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
                "Staff update is temporarily unavailable", correlationId);
        }
    }

    private static ResponseEntity<Map<String, String>> invalid(UUID correlationId) {
        return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
            "Invalid staff name update", correlationId);
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
                                                              String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message,
                "traceId", correlationId.toString()));
    }
}
