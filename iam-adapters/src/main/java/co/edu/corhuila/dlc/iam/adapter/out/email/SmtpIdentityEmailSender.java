package co.edu.corhuila.dlc.iam.adapter.out.email;

import co.edu.corhuila.dlc.iam.application.port.out.IdentityEmailSender;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationEmailSender;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
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
        send(email, token, correlationId, new Content(
            "Tu código de recuperación de contraseña - Di Lucca",
            "Recupera tu contraseña",
            "Recibimos una solicitud para restablecer la contraseña de tu cuenta. "
                + "Ingresa este código en la pantalla de recuperación para crear una nueva.",
            "15 minutos",
            "Si no solicitaste este cambio, ignora este correo: tu contraseña seguirá igual."));
    }

    @Override
    public void sendEmailVerification(String email, String token, UUID correlationId) {
        send(email, token, correlationId, new Content(
            "Tu código de verificación de cuenta - Di Lucca",
            "Activa tu cuenta",
            "Bienvenido a Di Lucca. Ingresa este código en la pantalla de activación "
                + "para verificar tu correo y empezar a usar tu cuenta.",
            "24 horas",
            "Si no esperabas este correo, puedes ignorarlo."));
    }

    private record Content(String subject, String title, String intro,
                           String lifetime, String ignoreNote) {
    }

    private void send(String email, String token, UUID correlationId, Content content) {
        if (email == null || email.isBlank() || token == null || token.isBlank()
            || correlationId == null) {
            throw new IllegalArgumentException("Invalid IAM identity email");
        }
        for (int attempt = 1; attempt <= 2; attempt++) {
            try {
                mail.send(build(email, token, content));
                LOG.log(System.Logger.Level.INFO,
                    "IAM identity email accepted by provider; correlationId=" + correlationId);
                return;
            } catch (MailException providerFailure) {
                LOG.log(System.Logger.Level.WARNING,
                    "IAM identity email attempt " + attempt + " failed; cause="
                        + providerFailure.getClass().getSimpleName()
                        + "; correlationId=" + correlationId);
                if (attempt == 2) {
                    throw new IllegalStateException(
                        "IAM identity email provider unavailable: "
                            + providerFailure.getClass().getSimpleName());
                }
            }
        }
    }

    private MimeMessage build(String email, String token, Content content) {
        try {
            MimeMessage message = mail.createMimeMessage();
            var helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(senderAddress, "Di Lucca");
            helper.setTo(email);
            helper.setSubject(content.subject());
            helper.setText(plainText(token, content), html(token, content));
            return message;
        } catch (MessagingException | java.io.UnsupportedEncodingException invalid) {
            throw new IllegalStateException("IAM identity email could not be composed");
        }
    }

    private static String plainText(String token, Content c) {
        return c.title() + "\n\n" + c.intro() + "\n\nTu código: " + token
            + "\n\nEl código vence en " + c.lifetime() + ". No lo compartas con nadie.\n"
            + c.ignoreNote() + "\n\nDi Lucca - Clínica odontológica\n";
    }

    private static String html(String token, Content c) {
        return """
            <!doctype html>
            <html lang="es"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1"></head>
            <body style="margin:0;padding:0;background:#eef5f4;font-family:Arial,Helvetica,sans-serif;color:#1f2933;">
            <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#eef5f4;padding:32px 12px;">
            <tr><td align="center">
            <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 16px rgba(15,23,42,.08);">
            <tr><td style="background:#20a99a;padding:22px 32px;">
              <span style="color:#ffffff;font-size:22px;font-weight:bold;letter-spacing:.5px;">DI LUCCA</span>
            </td></tr>
            <tr><td style="padding:32px 32px 8px;">
              <h1 style="margin:0 0 12px;font-size:22px;color:#0f766e;">%s</h1>
              <p style="margin:0;font-size:15px;line-height:1.6;color:#35616a;">%s</p>
            </td></tr>
            <tr><td align="center" style="padding:24px 32px;">
              <div style="display:inline-block;padding:16px 28px;background:#f0faf8;border:2px dashed #20a99a;border-radius:10px;font-family:'Courier New',monospace;font-size:28px;font-weight:bold;letter-spacing:4px;color:#0f766e;word-break:break-all;">%s</div>
              <p style="margin:14px 0 0;font-size:13px;color:#64748b;">Este código vence en <strong>%s</strong>.</p>
            </td></tr>
            <tr><td style="padding:0 32px 28px;">
              <p style="margin:0;padding:12px 14px;background:#fff8e6;border-radius:8px;font-size:13px;line-height:1.5;color:#7a5b00;">
                No compartas este código con nadie. El equipo de Di Lucca nunca te lo pedirá.</p>
              <p style="margin:16px 0 0;font-size:13px;line-height:1.5;color:#64748b;">%s</p>
            </td></tr>
            <tr><td style="background:#f7fafa;padding:16px 32px;font-size:12px;color:#94a3b8;text-align:center;">
              © Di Lucca · Clínica odontológica. Este es un correo automático, no lo respondas.
            </td></tr>
            </table></td></tr></table></body></html>
            """.formatted(escape(c.title()), escape(c.intro()), escape(token),
                escape(c.lifetime()), escape(c.ignoreNote()));
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
