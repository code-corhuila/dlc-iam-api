package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.in.ResetPassword;
import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordHasher;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordResetUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.ResetPasswordService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PasswordResetConfiguration {
    @Bean
    ResetPassword resetPassword(PasswordResetUnitOfWork unitOfWork,
                                ChallengeTokenHasher tokens, PasswordHasher passwords,
                                Clock iamClock) {
        return new ResetPasswordService(unitOfWork, tokens, passwords, iamClock);
    }
}
