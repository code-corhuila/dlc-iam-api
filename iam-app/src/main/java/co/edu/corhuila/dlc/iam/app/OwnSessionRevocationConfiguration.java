package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionRevocationUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.RevokeOwnSessionService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OwnSessionRevocationConfiguration {
    @Bean
    RevokeOwnSessionService revokeOwnSessionService(OwnSessionRevocationUnitOfWork unitOfWork,
                                                   Clock iamClock) {
        return new RevokeOwnSessionService(unitOfWork, iamClock);
    }
}
