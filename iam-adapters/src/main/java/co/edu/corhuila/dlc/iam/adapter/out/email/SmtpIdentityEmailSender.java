package co.edu.corhuila.dlc.iam.adapter.out.email;

import co.edu.corhuila.dlc.iam.application.port.out.IdentityEmailSender;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationEmailSender;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/** Sends IAM credentials only through TLS-required SMTP; never logs message contents. */
@Component
public final class SmtpIdentityEmailSender implements IdentityEmailSender, VerificationEmailSender {
    private static final System.Logger LOG = System.getLogger(SmtpIdentityEmailSender.class.getName());
    private final JavaMailSender mail;
    private final String senderAddress;

    public SmtpIdentityEmailSender(JavaMailSender mail,
                                   @Value("${IAM_EMAIL_FROM}") String senderAddress) {
        if (senderAddress == null || senderAddress.isBlank()) {
            throw new IllegalArgumentException("IAM email sender address is required");
        }
        this.mail = mail;
        this.senderAddress = senderAddress;
    }

    @Override
    public void sendPasswordRecovery(String email, String token, UUID correlationId) {
        send(email, token, correlationId, "Di Lucca password recovery",
            "Enter this recovery code in the IAM password reset form. It expires in 15 minutes: ");
    }

    @Override
    public void sendEmailVerification(String email, String token, UUID correlationId) {
        send(email, token, correlationId, "Di Lucca email verification",
            "Enter this verification code in the IAM verification form. It expires in 24 hours: ");
    }

    private void send(String email, String token, UUID correlationId,
                      String subject, String instruction) {
        if (email == null || email.isBlank() || token == null || token.isBlank()
            || correlationId == null) {
            throw new IllegalArgumentException("Invalid IAM identity email");
        }
        var message = new SimpleMailMessage();
        message.setFrom(senderAddress);
        message.setTo(email);
        message.setSubject(subject);
        message.setText(instruction + token + "\nDo not share this code.\n");
        for (int attempt = 1; attempt <= 2; attempt++) {
            try {
                mail.send(message);
                LOG.log(System.Logger.Level.INFO,
                    "IAM identity email accepted by provider; correlationId=" + correlationId);
                return;
            } catch (MailException providerFailure) {
                if (attempt == 2) {
                    LOG.log(System.Logger.Level.WARNING,
                        "IAM identity email provider failed; correlationId=" + correlationId);
                    throw new IllegalStateException("IAM identity email provider unavailable");
                }
            }
        }
    }
}
