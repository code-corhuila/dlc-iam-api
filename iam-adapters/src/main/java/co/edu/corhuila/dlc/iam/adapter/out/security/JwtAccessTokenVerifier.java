package co.edu.corhuila.dlc.iam.adapter.out.security;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenVerifier;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

@Component
public final class JwtAccessTokenVerifier implements AccessTokenVerifier {
    private final JwtDecoder decoder;

    public JwtAccessTokenVerifier(@Qualifier("staffJwtDecoder") JwtDecoder decoder) {
        this.decoder = decoder;
    }

    @Override
    public VerifiedAccessToken verify(String token) {
        try {
            Jwt jwt = decoder.decode(token);
            Object roles = jwt.getClaims().get("roles");
            if (jwt.getSubject() == null || jwt.getClaimAsString("sid") == null
                || jwt.getId() == null || jwt.getClaims().get("permissions") == null
                || !(roles instanceof List<?> list)
                || list.isEmpty() || list.stream().anyMatch(role -> !(role instanceof String))) {
                throw new IllegalArgumentException("Invalid staff token");
            }
            return new VerifiedAccessToken(UUID.fromString(jwt.getSubject()),
                UUID.fromString(jwt.getClaimAsString("sid")),
                list.stream().map(String.class::cast).toList());
        } catch (JwtException | ClassCastException invalid) {
            throw new IllegalArgumentException("Invalid staff token", invalid);
        }
    }
}
