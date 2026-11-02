package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.in.ResetPassword;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidRecoveryChallengeException;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.converter.HttpMessageNotReadableException;

@RestController
@RequestMapping("/api/v1/auth")
public final class PasswordResetController {
    private final ResetPassword resetPassword;

    public PasswordResetController(ResetPassword resetPassword) {
        this.resetPassword = resetPassword;
    }

    @PostMapping("/password-resets")
    public ResponseEntity<Map<String, String>> reset(@RequestBody(required = false) JsonNode body) {
        UUID correlationId = UUID.randomUUID();
        if (body == null || !body.isObject() || body.size() != 2
            || !body.has("token") || !body.get("token").isTextual()
            || !body.has("password") || !body.get("password").isTextual()) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid password reset request", correlationId);
        }
        String token = body.get("token").asText();
        String password = body.get("password").asText();
        if (token.isBlank() || token.length() > 512 || password.length() < 8
            || password.getBytes(StandardCharsets.UTF_8).length > 72
            || !password.matches("(?s).*[A-Z].*")
            || !password.matches("(?s).*[0-9].*")) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid password reset request", correlationId);
        }
        try {
            resetPassword.reset(token, password, correlationId);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("message", "Password reset completed"));
        } catch (InvalidRecoveryChallengeException invalid) {
            return error(HttpStatus.CONFLICT, "INVALID_CHALLENGE",
                "Invalid or expired recovery token", correlationId);
        } catch (IllegalArgumentException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid password reset request", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Password reset is temporarily unavailable", correlationId);
        }
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> malformedBody() {
        return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
            "Invalid password reset request", UUID.randomUUID());
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
                                                              String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message,
                "traceId", correlationId.toString()));
    }
}
