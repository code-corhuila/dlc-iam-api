package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.in.DisableStaffAccount;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class DisableStaffController {
    private final CurrentActorService actors;
    private final DisableStaffAccount accounts;
    private final ObjectMapper json;

    public DisableStaffController(CurrentActorService actors, DisableStaffAccount accounts,
                                  ObjectMapper json) {
        this.actors = actors;
        this.accounts = accounts;
        this.json = json;
    }

    @PostMapping("/api/v1/auth/staff/{id}/disablings")
    public ResponseEntity<?> disable(@PathVariable String id,
                                    @RequestHeader(value = HttpHeaders.AUTHORIZATION,
                                                   required = false) String authorization,
                                    @RequestHeader(value = "Idempotency-Key",
                                                   required = false) String key,
                                    @RequestBody(required = false) String rawBody) {
        UUID correlationId = UUID.randomUUID();
        try {
            var actor = actors.authenticate(authorization);
            if (!actor.roles().contains("ADMINISTRATOR")) {
                return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
            }
            UUID staffId;
            UUID idempotencyKey;
            JsonNode body;
            try {
                staffId = UUID.fromString(id);
                idempotencyKey = UUID.fromString(key);
                body = rawBody == null ? null : json.readTree(rawBody);
            } catch (IllegalArgumentException | NullPointerException | JsonProcessingException invalid) {
                return invalid(correlationId);
            }
            if (body == null || !body.isObject() || body.size() != 2
                || !body.has("reason") || !body.get("reason").isTextual()
                || !body.has("expectedVersion") || !body.get("expectedVersion").isIntegralNumber()
                || !body.get("expectedVersion").canConvertToLong()
                || body.get("expectedVersion").asLong() < 1) {
                return invalid(correlationId);
            }
            String reason = body.get("reason").asText();
            if (reason.isBlank() || !reason.equals(reason.strip()) || reason.length() > 1000) {
                return invalid(correlationId);
            }
            var result = accounts.disable(actor.userId(), staffId,
                body.get("expectedVersion").asLong(), reason, idempotencyKey, correlationId);
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
            return error(HttpStatus.CONFLICT, "CONFLICT", "Staff cannot be disabled", correlationId);
        } catch (IllegalArgumentException invalid) {
            return invalid(correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Staff disabling is temporarily unavailable", correlationId);
        }
    }

    private static ResponseEntity<Map<String, String>> invalid(UUID correlationId) {
        return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
            "Invalid staff disabling request", correlationId);
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
                                                              String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message,
                "traceId", correlationId.toString()));
    }
}
