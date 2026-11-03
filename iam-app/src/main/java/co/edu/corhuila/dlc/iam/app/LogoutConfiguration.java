package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.LogoutUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.usecase.LogoutService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class LogoutConfiguration {
    @Bean
    LogoutService logoutService(LogoutUnitOfWork store, RefreshCredential credential,
                                Clock iamClock) {
        return new LogoutService(store, credential, iamClock);
    }
}
