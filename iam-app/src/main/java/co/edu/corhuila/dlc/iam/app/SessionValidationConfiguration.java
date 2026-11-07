package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.SessionSnapshotReader;
import co.edu.corhuila.dlc.iam.application.usecase.ValidateSessionService;
import co.edu.corhuila.dlc.iam.adapter.out.security.RsaAccessTokenIssuer;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.time.Clock;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class SessionValidationConfiguration {
    @Bean
    Clock iamClock() {
        return Clock.systemUTC();
    }

    @Bean
    ValidateSessionService validateSessionService(SessionSnapshotReader reader, Clock iamClock) {
        return new ValidateSessionService(reader, iamClock);
    }

    @Bean("staffJwtDecoder")
    JwtDecoder staffJwtDecoder(RsaAccessTokenIssuer issuerKeys,
                               @Value("${IAM_JWT_ISSUER}") String issuer,
                               @Value("${IAM_JWT_AUDIENCE}") String audience) throws Exception {
        var keys = JWKSet.parse(Map.of("keys", issuerKeys.publicJwks()));
        var processor = new DefaultJWTProcessor<SecurityContext>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
            new ImmutableJWKSet<>(keys)));
        var decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(validator(issuer, audience));
        return decoder;
    }

    @Bean("serviceJwtDecoder")
    JwtDecoder serviceJwtDecoder(@Value("${IAM_INTERNAL_SERVICE_JWKS_URI}") String jwksUri,
                                 @Value("${IAM_INTERNAL_SERVICE_ISSUER}") String issuer,
                                 @Value("${IAM_INTERNAL_SERVICE_AUDIENCE}") String audience) {
        var decoder = NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
        decoder.setJwtValidator(validator(issuer, audience));
        return decoder;
    }

    private OAuth2TokenValidator<Jwt> validator(String issuer, String audience) {
        var defaults = JwtValidators.createDefaultWithIssuer(issuer);
        return jwt -> {
            var base = defaults.validate(jwt);
            if (base.hasErrors()) return base;
            if (jwt.getIssuedAt() == null || jwt.getExpiresAt() == null
                || !jwt.getAudience().contains(audience)) {
                return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Required claims or audience missing", null));
            }
            return OAuth2TokenValidatorResult.success();
        };
    }
}
