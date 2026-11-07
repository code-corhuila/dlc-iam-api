package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.adapter.out.security.RsaAccessTokenIssuer;
import java.util.List;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public final class PublicJwksController {
    private final RsaAccessTokenIssuer issuer;

    public PublicJwksController(RsaAccessTokenIssuer issuer) {
        this.issuer = issuer;
    }

    @GetMapping("/jwks")
    public ResponseEntity<Map<String, List<Map<String, Object>>>> read() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
            .body(Map.of("keys", issuer.publicJwks()));
    }
}
