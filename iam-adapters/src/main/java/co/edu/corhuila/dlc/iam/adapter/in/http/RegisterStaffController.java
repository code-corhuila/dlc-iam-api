package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.out.RegistrationUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.RegisterStaffService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class RegisterStaffController {
    private final CurrentActorService actors;
    private final RegisterStaffService registrations;
    private final ObjectMapper json;

    public RegisterStaffController(CurrentActorService actors, RegisterStaffService registrations,
                                   ObjectMapper json) {
        this.actors = actors;
        this.registrations = registrations;
        this.json = json;
    }

    @PostMapping("/api/v1/auth/register")
    public ResponseEntity<?> register(@RequestHeader(value = HttpHeaders.AUTHORIZATION,
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
            UUID requestKey;
            JsonNode body;
            try {
                requestKey = UUID.fromString(key);
                body = rawBody == null || rawBody.length() > 4096 ? null : json.readTree(rawBody);
            } catch (IllegalArgumentException | NullPointerException | JsonProcessingException invalid) {
                return invalid(correlationId);
            }
            if (body == null || !body.isObject() || body.size() != 4
                || !text(body, "email") || !text(body, "password")
                || !text(body, "name") || !text(body, "role")) {
                return invalid(correlationId);
            }
            RegistrationUnitOfWork.Staff staff = registrations.register(actor.userId(),
                body.get("email").asText(), body.get("password").asText(),
                body.get("name").asText(), body.get("role").asText(), requestKey, correlationId);
            var response = new StaffResponse(staff.id(), staff.email(), staff.name(),
                List.of(staff.role()), staff.status(), staff.createdAt(), staff.createdAt(),
                staff.version());
            return ResponseEntity.created(URI.create("/api/v1/auth/staff/" + staff.id()))
                .cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString()).body(response);
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication required", correlationId);
        } catch (SecurityException denied) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
        } catch (IllegalArgumentException invalid) {
            return invalid(correlationId);
        } catch (ConcurrentModificationException | DuplicateKeyException conflict) {
            return error(HttpStatus.CONFLICT, "CONFLICT", "Staff cannot be registered", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Registration temporarily unavailable", correlationId);
        }
    }

    private static boolean text(JsonNode body, String field) {
        return body.has(field) && body.get(field).isTextual();
    }

    private static ResponseEntity<Map<String, String>> invalid(UUID correlationId) {
        return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "Invalid registration request", correlationId);
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
                                                              String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message, "traceId", correlationId.toString()));
    }

    public record StaffResponse(UUID id, String email, String name, List<String> roles,
                                String status, java.time.Instant createdAt,
                                java.time.Instant updatedAt, long version) { }
}
