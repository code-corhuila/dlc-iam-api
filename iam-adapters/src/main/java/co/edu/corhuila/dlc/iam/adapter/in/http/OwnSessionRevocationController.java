package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.RevokeOwnSessionService;
import co.edu.corhuila.dlc.iam.application.usecase.SessionRevocationConflictException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/sessions")
public final class OwnSessionRevocationController {
    private static final Set<String> STAFF_ROLES = Set.of(
        "ADMINISTRATOR", "DENTIST", "SECRETARY_ASSISTANT");
    private final CurrentActorService actors;
    private final RevokeOwnSessionService revocations;
    private final ObjectMapper json;

    public OwnSessionRevocationController(CurrentActorService actors,
                                          RevokeOwnSessionService revocations, ObjectMapper json) {
        this.actors = actors;
        this.revocations = revocations;
        this.json = json;
    }

    @PostMapping("/{id}/revocations")
    public ResponseEntity<?> revoke(@PathVariable String id,
                                    @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                                    String authorization,
                                    @RequestHeader(value = "Idempotency-Key", required = false)
                                    String key,
                                    @RequestBody(required = false) String rawBody) {
        UUID correlationId = UUID.randomUUID();
        try {
            var actor = actors.authenticate(authorization);
            if (actor.roles().stream().noneMatch(STAFF_ROLES::contains)) {
                return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
            }
            UUID sessionId;
            UUID idempotencyKey;
            try {
                sessionId = UUID.fromString(id);
                idempotencyKey = UUID.fromString(key);
            } catch (IllegalArgumentException | NullPointerException invalid) {
                return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                    "Invalid session revocation request", correlationId);
            }
            JsonNode body;
            try {
                body = rawBody == null ? null : json.readTree(rawBody);
            } catch (JsonProcessingException malformed) {
                return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                    "Invalid session revocation request", correlationId);
            }
            if (body == null || !body.isObject() || body.size() != 1
                || !body.has("reason") || !body.get("reason").isTextual()
                || body.get("reason").asText().isBlank()
                || body.get("reason").asText().length() > 1000) {
                return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                    "Invalid session revocation request", correlationId);
            }
            revocations.revoke(actor.userId(), sessionId, idempotencyKey,
                body.get("reason").asText(), correlationId);
            return ResponseEntity.noContent().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString()).build();
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication required",
                correlationId);
        } catch (NoSuchElementException missing) {
            return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Session not found", correlationId);
        } catch (SessionRevocationConflictException conflict) {
            return error(HttpStatus.CONFLICT, conflict.code(), "Session revocation conflict",
                correlationId);
        } catch (IllegalArgumentException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid session revocation request", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Session revocation is temporarily unavailable", correlationId);
        }
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
                                                              String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message,
                "traceId", correlationId.toString()));
    }
}
