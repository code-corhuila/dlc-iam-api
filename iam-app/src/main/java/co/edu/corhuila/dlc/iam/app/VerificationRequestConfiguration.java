package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryTokenGenerator;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationEmailSender;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationRequestLimiter;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationRequestUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.RequestEmailVerificationService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class VerificationRequestConfiguration {
    @Bean
    RequestEmailVerificationService requestEmailVerificationService(
            VerificationRequestUnitOfWork unitOfWork, VerificationRequestLimiter limiter,
            RecoveryTokenGenerator tokens, ChallengeTokenHasher hasher,
            VerificationEmailSender emailSender, Clock iamClock) {
        return new RequestEmailVerificationService(unitOfWork, limiter, tokens,
            hasher, emailSender, iamClock);
    }
}
