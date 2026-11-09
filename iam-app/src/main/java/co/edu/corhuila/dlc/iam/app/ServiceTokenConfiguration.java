package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.adapter.out.security.RsaServiceTokenSigner;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.ServiceClientDirectory;
import co.edu.corhuila.dlc.iam.application.usecase.IssueServiceTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** ADR-020 issuer, enabled only when the service signing key is configured; token files keep working otherwise. */
@Configuration
@ConditionalOnProperty("IAM_SERVICE_JWT_PRIVATE_KEY_PEM")
public class ServiceTokenConfiguration {
    @Bean
    RsaServiceTokenSigner serviceTokenSigner(@Value("${IAM_SERVICE_JWT_PRIVATE_KEY_PEM}") String privatePem,
                                             @Value("${IAM_SERVICE_JWT_PUBLIC_KEY_PEM}") String publicPem,
                                             @Value("${IAM_SERVICE_JWT_KID}") String kid,
                                             @Value("${IAM_INTERNAL_SERVICE_ISSUER}") String issuer,
                                             ObjectMapper json) {
        return new RsaServiceTokenSigner(privatePem, publicPem, kid, issuer, json);
    }

    @Bean
    IssueServiceTokenService issueServiceTokenService(ServiceClientDirectory clients, PasswordVerifier secrets,
                                                      RsaServiceTokenSigner signer, Clock iamClock) {
        return new IssueServiceTokenService(clients, secrets, signer, iamClock);
    }
}
