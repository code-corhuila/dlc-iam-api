package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.IdentityEmailSender;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryRequestLimiter;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryRequestUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryTokenGenerator;
import co.edu.corhuila.dlc.iam.application.usecase.RequestPasswordRecoveryService;
import java.time.Clock;
import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RecoveryRequestConfiguration {
    @Bean
    RequestPasswordRecoveryService requestPasswordRecoveryService(
            RecoveryRequestUnitOfWork unitOfWork, RecoveryRequestLimiter limiter,
            RecoveryTokenGenerator tokens, ChallengeTokenHasher hasher,
            IdentityEmailSender emailSender, Clock iamClock) {
        return new RequestPasswordRecoveryService(unitOfWork, limiter, tokens,
            hasher, emailSender, iamClock, Duration.ofMinutes(15));
    }
}
