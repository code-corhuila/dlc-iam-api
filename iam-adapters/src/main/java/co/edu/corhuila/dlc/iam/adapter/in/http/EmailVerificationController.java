package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.in.VerifyStaffEmail;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidVerificationChallengeException;
import com.fasterxml.jackson.databind.JsonNode;
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
public final class EmailVerificationController {
    private final VerifyStaffEmail verification;

    public EmailVerificationController(VerifyStaffEmail verification) {
        this.verification = verification;
    }

    @PostMapping("/email-verifications")
    public ResponseEntity<Map<String, String>> verify(@RequestBody(required = false) JsonNode body) {
        UUID correlationId = UUID.randomUUID();
        if (body == null || !body.isObject() || body.size() != 1
            || !body.has("token") || !body.get("token").isTextual()
            || body.get("token").asText().isBlank()
            || body.get("token").asText().length() > 512) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid verification request", correlationId);
        }
        try {
            verification.verify(body.get("token").asText(), correlationId);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("message", "Email verified"));
        } catch (InvalidVerificationChallengeException invalid) {
            return error(HttpStatus.CONFLICT, "INVALID_CHALLENGE",
                "Invalid or expired verification token", correlationId);
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
