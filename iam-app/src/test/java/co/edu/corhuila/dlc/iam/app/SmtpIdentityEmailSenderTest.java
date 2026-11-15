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
import static org.mockito.Mockito.when;

import co.edu.corhuila.dlc.iam.adapter.out.email.SmtpIdentityEmailSender;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;

class SmtpIdentityEmailSenderTest {
    private final JavaMailSender mail = mock(JavaMailSender.class);
    private final SmtpIdentityEmailSender sender =
        new SmtpIdentityEmailSender(mail, "identity@example.test");

    @BeforeEach
    void mimeMessages() {
        when(mail.createMimeMessage())
            .thenAnswer(invocation -> new MimeMessage(Session.getInstance(new Properties())));
    }

    private MimeMessage sent() {
        var messages = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mail).send(messages.capture());
        return messages.getValue();
    }

    private static String raw(MimeMessage message) throws Exception {
        message.saveChanges();
        var text = new StringBuilder();
        collect(message, text);
        return text.toString();
    }

    private static void collect(jakarta.mail.Part part, StringBuilder text) throws Exception {
        text.append(part.getContentType()).append('\n');
        Object content = part.getContent();
        if (content instanceof jakarta.mail.Multipart multipart) {
            for (int i = 0; i < multipart.getCount(); i++) {
                collect(multipart.getBodyPart(i), text);
            }
        } else {
            text.append(content).append('\n');
        }
    }

    @Test
    void recoveryMessageContainsOnlyManualCodeWithNoTokenUrl() throws Exception {
        sender.sendPasswordRecovery("staff@example.test", "opaque-code", UUID.randomUUID());
        var message = sent();
        assertEquals("identity@example.test",
            ((InternetAddress) message.getFrom()[0]).getAddress());
        assertEquals("staff@example.test", message.getAllRecipients()[0].toString());
        var body = raw(message);
        assertTrue(body.contains("opaque-code"));
        assertTrue(body.contains("15 minutos"));
        assertTrue(body.contains("text/html"));
        assertFalse(body.contains("http://") || body.contains("https://"));
    }

    @Test
    void verificationMessageUsesItsOwnPurposeAndLifetime() throws Exception {
        sender.sendEmailVerification("staff@example.test", "verify-code", UUID.randomUUID());
        var message = sent();
        assertTrue(message.getSubject().contains("verificación"));
        assertTrue(raw(message).contains("24 horas"));
    }

    @Test
    void codeIsHtmlEscaped() throws Exception {
        sender.sendPasswordRecovery("staff@example.test", "<b>x</b>", UUID.randomUUID());
        var body = raw(sent());
        assertTrue(body.contains("&lt;b&gt;x&lt;/b&gt;"));
    }

    @Test
    void providerFailureIsRetriedOnceAndSanitized() {
        doThrow(new MailSendException("secret token or email from provider"))
            .when(mail).send(any(MimeMessage.class));
        var failure = assertThrows(IllegalStateException.class, () -> sender.sendPasswordRecovery(
            "staff@example.test", "secret-token", UUID.randomUUID()));
        verify(mail, times(2)).send(any(MimeMessage.class));
        assertFalse(failure.getMessage().contains("staff@example.test"));
        assertFalse(failure.getMessage().contains("secret-token"));
        assertEquals(null, failure.getCause());
    }
}
