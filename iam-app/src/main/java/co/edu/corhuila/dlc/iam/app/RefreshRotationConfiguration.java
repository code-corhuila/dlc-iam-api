package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshRotationUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.RotateRefreshService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class RefreshRotationConfiguration {
    @Bean
    RotateRefreshService rotateRefreshService(RefreshRotationUnitOfWork store,
                                              RefreshCredential credentials,
                                              AccessTokenIssuer tokens, Clock iamClock) {
        return new RotateRefreshService(store, credentials, tokens, iamClock);
    }
}
