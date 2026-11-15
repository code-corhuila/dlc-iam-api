package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.LoginIpAttemptWindow;
import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.usecase.IpLoginLimiter;
import co.edu.corhuila.dlc.iam.application.usecase.LoginService;
import java.time.Clock;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class LoginConfiguration {
    @Bean
    LoginService loginService(LoginUnitOfWork store, PasswordVerifier passwords,
                              RefreshCredential refresh, AccessTokenIssuer tokens, Clock clock) {
        return new LoginService(store, passwords, refresh, tokens, clock);
    }

    @Bean
    IpLoginLimiter ipLoginLimiter(LoginIpAttemptWindow attempts,
                                  @Value("${IAM_LOGIN_IP_DIGEST_KEY_BASE64}") String key,
                                  Clock clock) {
        return new IpLoginLimiter(attempts, Base64.getDecoder().decode(key), clock);
    }
}
