package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import java.util.Map;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.transaction.TransactionException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public final class LoginErrors {
    @ExceptionHandler(InvalidLoginException.class)
    public ResponseEntity<Map<String, String>> invalid() {
        return ResponseEntity.status(401)
            .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"di-lucca\"")
            .header(HttpHeaders.CACHE_CONTROL, "no-store")
            .body(Map.of("error", "UNAUTHORIZED",
                "message", "Authentication could not be completed."));
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<Map<String, String>> badRequest() {
        return ResponseEntity.badRequest()
            .header(HttpHeaders.CACHE_CONTROL, "no-store")
            .body(Map.of("error", "VALIDATION_ERROR", "message", "Invalid input data"));
    }

    @ExceptionHandler({DataAccessException.class, TransactionException.class})
    public ResponseEntity<Map<String, String>> unavailable() {
        return ResponseEntity.status(503)
            .header(HttpHeaders.CACHE_CONTROL, "no-store")
            .body(Map.of("error", "SERVICE_UNAVAILABLE",
                "message", "Authentication service is temporarily unavailable"));
    }
}
