package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import co.edu.corhuila.dlc.iam.adapter.out.email.SmtpIdentityEmailSender;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

class SmtpIdentityEmailSenderTest {
    private final JavaMailSender mail = mock(JavaMailSender.class);
    private final SmtpIdentityEmailSender sender =
        new SmtpIdentityEmailSender(mail, "identity@example.test");

    @Test
    void recoveryMessageContainsOnlyManualCodeWithNoTokenUrl() {
        sender.sendPasswordRecovery("staff@example.test", "opaque-code", UUID.randomUUID());
        var messages = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mail).send(messages.capture());
        var message = messages.getValue();
        assertEquals("identity@example.test", message.getFrom());
        assertEquals("staff@example.test", message.getTo()[0]);
        assertTrue(message.getText().contains("opaque-code"));
        assertTrue(message.getText().contains("15 minutes"));
        assertFalse(message.getText().contains("http"));
    }

    @Test
    void verificationMessageUsesItsOwnPurposeAndLifetime() {
        sender.sendEmailVerification("staff@example.test", "verify-code", UUID.randomUUID());
        var messages = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mail).send(messages.capture());
        assertTrue(messages.getValue().getSubject().contains("verification"));
        assertTrue(messages.getValue().getText().contains("24 hours"));
    }

    @Test
    void providerFailureIsRetriedOnceAndSanitized() {
        doThrow(new MailSendException("secret token or email from provider"))
            .when(mail).send(any(SimpleMailMessage.class));
        var failure = assertThrows(IllegalStateException.class, () -> sender.sendPasswordRecovery(
            "staff@example.test", "secret-token", UUID.randomUUID()));
        verify(mail, times(2)).send(any(SimpleMailMessage.class));
        assertFalse(failure.getMessage().contains("staff@example.test"));
        assertFalse(failure.getMessage().contains("secret-token"));
        assertEquals(null, failure.getCause());
    }
}
