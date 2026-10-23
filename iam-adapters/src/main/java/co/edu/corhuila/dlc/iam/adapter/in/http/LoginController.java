package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.adapter.out.security.RsaAccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public final class LoginController {
    private final LoginUseCase login;
    private final RsaAccessTokenIssuer signing;

    public LoginController(LoginUseCase login, RsaAccessTokenIssuer signing) {
        this.login = login;
        this.signing = signing;
    }

    @PostMapping("/login")
    public ResponseEntity<Tokens> login(@RequestBody LoginBody body,
                                        HttpServletRequest request) {
        UUID correlationId = UUID.randomUUID();
        var result = login.login(body.email(), body.password(), correlationId,
            request.getRemoteAddr());
        String refreshCookie = ResponseCookie.from("dlc_refresh", result.refreshToken())
            .httpOnly(true).secure(true).sameSite("Strict")
            .path("/api/v1/auth").maxAge(Duration.ofDays(7)).build().toString();
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, refreshCookie)
            .header("X-Correlation-Id", correlationId.toString())
            .cacheControl(CacheControl.noStore())
            .body(new Tokens(result.accessToken(), 3600, result.user()));
    }

    @GetMapping("/jwks")
    public Map<String, List<Map<String, Object>>> jwks() {
        return Map.of("keys", signing.publicJwks());
    }

    public record LoginBody(String email, String password) { }
    public record Tokens(String accessToken, int expiresIn, LoginUseCase.Staff user) { }
}
