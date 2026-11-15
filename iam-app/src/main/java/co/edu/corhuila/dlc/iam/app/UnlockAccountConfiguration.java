package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.in.UnlockAccount;
import co.edu.corhuila.dlc.iam.application.port.out.UnlockAccountUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.UnlockAccountService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class UnlockAccountConfiguration {
    @Bean
    UnlockAccount unlockAccount(UnlockAccountUnitOfWork unitOfWork, Clock iamClock) {
        return new UnlockAccountService(unitOfWork, iamClock);
    }
}
