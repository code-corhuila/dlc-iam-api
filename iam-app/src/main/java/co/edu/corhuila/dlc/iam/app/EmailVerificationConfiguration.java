package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.in.VerifyStaffEmail;
import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.EmailVerificationUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.VerifyStaffEmailService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EmailVerificationConfiguration {
    @Bean
    VerifyStaffEmail verifyStaffEmail(EmailVerificationUnitOfWork unitOfWork,
                                     ChallengeTokenHasher hasher, Clock iamClock) {
        return new VerifyStaffEmailService(unitOfWork, hasher, iamClock);
    }
}
