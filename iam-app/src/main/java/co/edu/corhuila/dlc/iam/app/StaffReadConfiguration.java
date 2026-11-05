package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.StaffReader;
import co.edu.corhuila.dlc.iam.application.usecase.ReadStaffService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StaffReadConfiguration {
    @Bean
    ReadStaffService readStaffService(StaffReader reader) {
        return new ReadStaffService(reader);
    }
}
