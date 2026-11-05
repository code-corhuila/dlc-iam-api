package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.RecoveryRateLimitedException;
import co.edu.corhuila.dlc.iam.application.usecase.RequestPasswordRecoveryService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public final class PasswordRecoveryRequestController {
    private final RequestPasswordRecoveryService recovery;

    public PasswordRecoveryRequestController(RequestPasswordRecoveryService recovery) {
        this.recovery = recovery;
    }

    @PostMapping("/password-recovery-requests")
    public ResponseEntity<Map<String, String>> request(@RequestBody(required = false) JsonNode body,
                                                        HttpServletRequest request) {
        UUID correlationId = UUID.randomUUID();
        if (body == null || !body.isObject() || body.size() != 1
            || !body.has("email") || !body.get("email").isTextual()) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid recovery request", correlationId);
        }
        try {
            // Forwarded headers are not trusted until a proxy policy identifies a trusted hop.
            recovery.request(body.get("email").asText(), request.getRemoteAddr(), correlationId);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("message", "If the address is eligible, recovery instructions will be sent."));
        } catch (RecoveryRateLimitedException limited) {
            return error(HttpStatus.TOO_MANY_REQUESTS, "TOO_MANY_REQUESTS",
                "Too many recovery requests", correlationId);
        } catch (IllegalArgumentException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid recovery request", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Recovery is temporarily unavailable", correlationId);
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
