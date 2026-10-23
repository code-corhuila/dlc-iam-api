package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.LoginAttemptLimiter;
import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.usecase.LoginService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoginConfiguration {
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    LoginUseCase loginUseCase(LoginUnitOfWork unitOfWork, LoginAttemptLimiter limiter,
                              PasswordVerifier passwords,
                              RefreshCredential refreshCredentials,
                              AccessTokenIssuer tokens, Clock clock) {
        return new LoginService(unitOfWork, limiter, passwords, refreshCredentials,
            tokens, clock);
    }
}
