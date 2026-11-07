package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionReader;
import co.edu.corhuila.dlc.iam.application.usecase.ListOwnSessionsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class OwnSessionListConfiguration {
    @Bean
    ListOwnSessionsService listOwnSessionsService(OwnSessionReader reader) {
        return new ListOwnSessionsService(reader);
    }
}
