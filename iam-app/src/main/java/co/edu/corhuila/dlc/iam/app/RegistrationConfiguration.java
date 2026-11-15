package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.adapter.out.security.HmacRegistrationRequestProof;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordHasher;
import co.edu.corhuila.dlc.iam.application.port.out.RegistrationRequestProof;
import co.edu.corhuila.dlc.iam.application.port.out.RegistrationUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryTokenGenerator;
import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationEmailSender;
import co.edu.corhuila.dlc.iam.application.usecase.RegisterStaffService;
import java.time.Clock;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class RegistrationConfiguration {
    @Bean
    RegistrationRequestProof registrationRequestProof(
            @Value("${IAM_REGISTRATION_PROOF_KEY_BASE64}") String key) {
        return new HmacRegistrationRequestProof(Base64.getDecoder().decode(key));
    }

    @Bean
    RegisterStaffService registerStaffService(RegistrationUnitOfWork unitOfWork,
            PasswordHasher passwords, RegistrationRequestProof proofs, Clock iamClock,
            RecoveryTokenGenerator tokens, ChallengeTokenHasher hasher,
            VerificationEmailSender emailSender) {
        return new RegisterStaffService(unitOfWork, passwords, proofs, iamClock,
            tokens, hasher, emailSender);
    }
}
