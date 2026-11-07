package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.application.port.in.ReplaceRoleAssignments;
import co.edu.corhuila.dlc.iam.application.port.out.RoleAssignmentUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.ReplaceRoleAssignmentsService;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class RoleAssignmentConfiguration {
    @Bean
    ReplaceRoleAssignments replaceRoleAssignments(RoleAssignmentUnitOfWork unitOfWork,
                                                  Clock iamClock) {
        return new ReplaceRoleAssignmentsService(unitOfWork, iamClock);
    }
}
