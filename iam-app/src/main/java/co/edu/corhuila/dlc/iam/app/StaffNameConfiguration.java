package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.StaffNameUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.UpdateStaffNameService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class StaffNameConfiguration {
    @Bean
    UpdateStaffNameService updateStaffNameService(StaffNameUnitOfWork unitOfWork, Clock iamClock) {
        return new UpdateStaffNameService(unitOfWork, iamClock);
    }
}
