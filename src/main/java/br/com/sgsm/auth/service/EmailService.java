package br.com.sgsm.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String remetente;

    @Value("${app.url:http://localhost:3001}")
    private String appUrl;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Async
    public void enviarBoasVindas(String destinatario, String nome, String perfil, String senha) {
        try {
            enviar(destinatario,
                    "Bem-vindo ao SGSM — Seus dados de acesso",
                    corpoBoasVindas(nome, perfil, destinatario, senha));
        } catch (Exception e) {
            log.error("Falha ao enviar e-mail de boas-vindas para {}", destinatario, e);
        }
    }

    @Async
    public void enviarLinkResetSenha(String destinatario, String nome, String token) {
        try {
            enviar(destinatario,
                    "SGSM — Redefinição de senha",
                    corpoResetSenha(nome, token));
        } catch (Exception e) {
            log.error("Falha ao enviar e-mail de reset de senha para {}", destinatario, e);
        }
    }

    @Async
    public void enviarConfirmacaoReset(String destinatario, String nome) {
        try {
            enviar(destinatario,
                    "SGSM — Senha alterada com sucesso",
                    corpoConfirmacaoReset(nome));
        } catch (Exception e) {
            log.error("Falha ao enviar e-mail de confirmação de reset para {}", destinatario, e);
        }
    }

    private void enviar(String destinatario, String assunto, String corpo) throws MessagingException {
        MimeMessage msg = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(msg, "UTF-8");
        helper.setFrom(remetente);
        helper.setTo(destinatario);
        helper.setSubject(assunto);
        helper.setText(corpo, true);
        mailSender.send(msg);
    }

    private String corpoBoasVindas(String nome, String perfil, String email, String senha) {
        return """
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
                  <h2 style="color:#0e7490">Olá, %s!</h2>
                  <p>Seu cadastro no <strong>SGSM</strong> foi realizado com sucesso.</p>
                  <table style="border-collapse:collapse;width:100%%">
                    <tr>
                      <td style="padding:8px;background:#f0f9ff;width:180px"><strong>Perfil</strong></td>
                      <td style="padding:8px">%s</td>
                    </tr>
                    <tr>
                      <td style="padding:8px;background:#f0f9ff"><strong>Usuário (e-mail)</strong></td>
                      <td style="padding:8px">%s</td>
                    </tr>
                    <tr>
                      <td style="padding:8px;background:#f0f9ff"><strong>Senha</strong></td>
                      <td style="padding:8px"><code style="font-size:15px;letter-spacing:1px">%s</code></td>
                    </tr>
                  </table>
                  <p style="margin-top:24px">
                    <a href="%s"
                       style="background:#0e7490;color:white;padding:12px 24px;
                              border-radius:6px;text-decoration:none;font-weight:bold">
                      Acessar o SGSM
                    </a>
                  </p>
                  <hr style="margin-top:32px;border:none;border-top:1px solid #e2e8f0"/>
                  <p style="font-size:12px;color:#64748b">
                    Se você não solicitou este cadastro, entre em contato com o suporte.
                  </p>
                </div>
                """.formatted(nome, perfil, email, senha, appUrl);
    }

    private String corpoResetSenha(String nome, String token) {
        String link = appUrl + "/resetar-senha?token=" + token;
        return """
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
                  <h2 style="color:#0e7490">Olá, %s!</h2>
                  <p>Recebemos uma solicitação para redefinir a senha da sua conta no SGSM.</p>
                  <p>Clique no botão abaixo para criar uma nova senha:</p>
                  <p style="margin-top:24px">
                    <a href="%s"
                       style="background:#0e7490;color:white;padding:12px 24px;
                              border-radius:6px;text-decoration:none;font-weight:bold">
                      Redefinir minha senha
                    </a>
                  </p>
                  <p style="color:#ef4444;margin-top:16px">
                    <strong>Este link expira em 2 horas.</strong>
                  </p>
                  <hr style="margin-top:32px;border:none;border-top:1px solid #e2e8f0"/>
                  <p style="font-size:12px;color:#64748b">
                    Se você não solicitou a redefinição de senha, ignore este e-mail.
                    Sua senha permanece a mesma.
                  </p>
                </div>
                """.formatted(nome, link);
    }

    private String corpoConfirmacaoReset(String nome) {
        return """
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
                  <h2 style="color:#0e7490">Olá, %s!</h2>
                  <p>Sua senha no <strong>SGSM</strong> foi alterada com sucesso.</p>
                  <p>Se você não realizou essa alteração, entre em contato com o
                  suporte imediatamente.</p>
                </div>
                """.formatted(nome);
    }
}
