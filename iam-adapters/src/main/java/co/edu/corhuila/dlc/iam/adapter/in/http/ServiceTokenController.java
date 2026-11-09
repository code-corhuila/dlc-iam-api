package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.adapter.out.security.RsaServiceTokenSigner;
import co.edu.corhuila.dlc.iam.application.usecase.IssueServiceTokenService;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * POST /internal/v1/service-tokens and GET /internal/v1/service-jwks (internal-coordination.yaml, ADR-020).
 * Private listener only; the caller authenticates with HTTP Basic client credentials, never a service JWT.
 * Present only when the service signing key is configured.
 */
@RestController
@ConditionalOnProperty("IAM_SERVICE_JWT_PRIVATE_KEY_PEM")
public class ServiceTokenController {
    private static final Set<String> FIELDS = Set.of("audience", "scope");

    private final IssueServiceTokenService tokens;
    private final RsaServiceTokenSigner keys;

    public ServiceTokenController(IssueServiceTokenService tokens, RsaServiceTokenSigner keys) {
        this.tokens = tokens;
        this.keys = keys;
    }

    @PostMapping("/internal/v1/service-tokens")
    public ResponseEntity<?> issue(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                                   String authorization, @RequestBody(required = false) Map<String, Object> body) {
        String[] credentials = basic(authorization);
        if (credentials == null) return unauthorized();
        if (body == null || !FIELDS.containsAll(body.keySet())
            || !(body.get("audience") instanceof String audience) || !(body.get("scope") instanceof String scope)) {
            return ResponseEntity.badRequest().build();
        }
        try {
            var issued = tokens.issue(credentials[0], credentials[1], audience, scope);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Map.of(
                "accessToken", issued.accessToken(), "tokenType", "Bearer",
                "expiresIn", issued.expiresIn(), "scope", issued.scope()));
        } catch (IssueServiceTokenService.InvalidClientException invalid) {
            return unauthorized();
        } catch (IssueServiceTokenService.ScopeNotGrantedException forbidden) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (IllegalArgumentException malformed) {
            return ResponseEntity.badRequest().build();
        } catch (DataAccessException unavailable) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }

    @GetMapping("/internal/v1/service-jwks")
    public ResponseEntity<?> jwks() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Map.of("keys", keys.publicJwks()));
    }

    private static String[] basic(String authorization) {
        if (authorization == null || !authorization.startsWith("Basic ")) return null;
        try {
            String decoded = new String(Base64.getDecoder().decode(authorization.substring(6).trim()),
                StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            return colon > 0 ? new String[] {decoded.substring(0, colon), decoded.substring(colon + 1)} : null;
        } catch (IllegalArgumentException malformed) {
            return null;
        }
    }

    private static ResponseEntity<?> unauthorized() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"internal\"").build();
    }
}
