package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.RecoveryRateLimitedException;
import co.edu.corhuila.dlc.iam.application.usecase.RequestEmailVerificationService;
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
public final class EmailVerificationRequestController {
    private final RequestEmailVerificationService verification;
    private final TrustedGatewayClientAddress clientAddress;

    public EmailVerificationRequestController(RequestEmailVerificationService verification,
                                              TrustedGatewayClientAddress clientAddress) {
        this.verification = verification;
        this.clientAddress = clientAddress;
    }

    @PostMapping("/email-verification-requests")
    public ResponseEntity<Map<String, String>> request(@RequestBody(required = false) JsonNode body,
                                                        HttpServletRequest request) {
        UUID correlationId = UUID.randomUUID();
        if (body == null || !body.isObject() || body.size() != 1
            || !body.has("email") || !body.get("email").isTextual()) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid verification request", correlationId);
        }
        try {
            verification.request(body.get("email").asText(),
                clientAddress.resolve(request).getHostAddress(), correlationId);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("message", "If the address is eligible, verification instructions will be sent."));
        } catch (RecoveryRateLimitedException limited) {
            return error(HttpStatus.TOO_MANY_REQUESTS, "TOO_MANY_REQUESTS",
                "Too many verification requests", correlationId);
        } catch (IllegalArgumentException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid verification request", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Verification is temporarily unavailable", correlationId);
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
