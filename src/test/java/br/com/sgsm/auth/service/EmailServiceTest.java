package br.com.sgsm.auth.service;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Properties;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    private EmailService service;

    @BeforeEach
    void setUp() {
        service = new EmailService(mailSender);
        ReflectionTestUtils.setField(service, "remetente", "noreply@sgsm.com.br");
        ReflectionTestUtils.setField(service, "appUrl", "http://localhost:3001");
    }

    private MimeMessage mimeMessage() {
        return new MimeMessage(Session.getInstance(new Properties()));
    }

    @Test
    void enviarBoasVindas_deveEnviarEmailComDadosDeAcesso() {
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage());

        service.enviarBoasVindas("a@a.com", "Nome Teste", "PACIENTE", "senha123");

        verify(mailSender).send(any(MimeMessage.class));
    }

    @Test
    void enviarLinkResetSenha_deveEnviarEmailComLinkDeReset() {
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage());

        service.enviarLinkResetSenha("a@a.com", "Nome Teste", "token-123");

        verify(mailSender).send(any(MimeMessage.class));
    }

    @Test
    void enviarConfirmacaoReset_deveEnviarEmailDeConfirmacao() {
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage());

        service.enviarConfirmacaoReset("a@a.com", "Nome Teste");

        verify(mailSender).send(any(MimeMessage.class));
    }

    @Test
    void enviarBoasVindas_deveEngolirExcecao_quandoEnvioFalha() {
        when(mailSender.createMimeMessage()).thenThrow(new RuntimeException("smtp indisponivel"));

        service.enviarBoasVindas("a@a.com", "Nome Teste", "PACIENTE", "senha123");

        verify(mailSender, never()).send(any(MimeMessage.class));
    }
}
