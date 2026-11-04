package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.in.DisableStaffAccount;
import co.edu.corhuila.dlc.iam.application.port.out.DisableStaffUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.DisableStaffAccountService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class DisableStaffConfiguration {
    @Bean
    DisableStaffAccount disableStaffAccount(DisableStaffUnitOfWork unitOfWork, Clock iamClock) {
        return new DisableStaffAccountService(unitOfWork, iamClock);
    }
}
