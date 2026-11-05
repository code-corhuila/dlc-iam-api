package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.in.EnableStaffAccount;
import co.edu.corhuila.dlc.iam.application.port.out.EnableStaffUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.EnableStaffAccountService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class EnableStaffConfiguration {
    @Bean
    EnableStaffAccount enableStaffAccount(EnableStaffUnitOfWork unitOfWork, Clock iamClock) {
        return new EnableStaffAccountService(unitOfWork, iamClock);
    }
}
