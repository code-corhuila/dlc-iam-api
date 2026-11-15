package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.LogoutUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.usecase.CookieCsrfProofService;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class CookieCsrfConfiguration {
    @Bean
    CookieCsrfProofService cookieCsrfProofService(LogoutUnitOfWork sessions,
                                                 RefreshCredential credentials,
                                                 @Value("${IAM_CSRF_KEY_BASE64}") String key,
                                                 Clock iamClock) {
        return new CookieCsrfProofService(sessions, credentials,
            Base64.getDecoder().decode(key), iamClock, new SecureRandom());
    }
}
