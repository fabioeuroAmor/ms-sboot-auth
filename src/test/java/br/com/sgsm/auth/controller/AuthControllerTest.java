package br.com.sgsm.auth.controller;

import br.com.sgsm.auth.dto.AlterarSenhaRequest;
import br.com.sgsm.auth.dto.EsqueciSenhaRequest;
import br.com.sgsm.auth.dto.LoginRequest;
import br.com.sgsm.auth.dto.LoginResponse;
import br.com.sgsm.auth.dto.LogoutRequest;
import br.com.sgsm.auth.dto.MeResponse;
import br.com.sgsm.auth.dto.RefreshRequest;
import br.com.sgsm.auth.dto.RefreshResponse;
import br.com.sgsm.auth.dto.RegistrarRequest;
import br.com.sgsm.auth.dto.RegistrarResponse;
import br.com.sgsm.auth.dto.ResetarSenhaRequest;
import br.com.sgsm.auth.service.AuthService;
import br.com.sgsm.auth.service.ResetSenhaService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;
    @Mock
    private ResetSenhaService resetSenhaService;

    private AuthController controller;

    @BeforeEach
    void setUp() {
        controller = new AuthController(authService, resetSenhaService);
    }

    @Test
    void registrar_deveRetornarCreatedComCorpoDoService() {
        var request = new RegistrarRequest("a@a.com", "senha123", "PACIENTE", UUID.randomUUID());
        var esperado = new RegistrarResponse();
        when(authService.registrar(request)).thenReturn(esperado);

        var resposta = controller.registrar(request);

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(resposta.getBody()).isSameAs(esperado);
    }

    @Test
    void login_deveRetornarOkComCorpoDoService() {
        var request = new LoginRequest("a@a.com", "senha123");
        var esperado = new LoginResponse("access", "refresh", 900L);
        when(authService.login(request)).thenReturn(esperado);

        var resposta = controller.login(request);

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resposta.getBody()).isSameAs(esperado);
    }

    @Test
    void me_deveRetornarOkComCorpoDoService() {
        var esperado = new MeResponse();
        when(authService.me("Bearer token")).thenReturn(esperado);

        var resposta = controller.me("Bearer token");

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resposta.getBody()).isSameAs(esperado);
    }

    @Test
    void refresh_deveRetornarOkComCorpoDoService() {
        var request = new RefreshRequest("refresh-token");
        var esperado = new RefreshResponse("novo-access", "novo-refresh", 900L);
        when(authService.refresh(request)).thenReturn(esperado);

        var resposta = controller.refresh(request);

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resposta.getBody()).isSameAs(esperado);
    }

    @Test
    void logout_deveRetornarNoContentEChamarServiceComToken() {
        var request = new LogoutRequest("refresh-token");

        var resposta = controller.logout(request, null);

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(resposta.getBody()).isNull();
        verify(authService).logout("refresh-token", null);
    }

    @Test
    void esqueciSenha_deveRetornarOkEChamarResetSenhaService() {
        var request = new EsqueciSenhaRequest("a@a.com");

        var resposta = controller.esqueciSenha(request);

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(resetSenhaService).solicitarReset("a@a.com");
    }

    @Test
    void resetarSenha_deveRetornarNoContentEChamarResetSenhaService() {
        var request = new ResetarSenhaRequest("token-123", "novaSenha");

        var resposta = controller.resetarSenha(request);

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(resetSenhaService).resetarSenha("token-123", "novaSenha");
    }

    @Test
    void alterarSenha_deveRetornarNoContentEChamarResetSenhaService() {
        var request = new AlterarSenhaRequest("senhaAtual", "novaSenha");

        var resposta = controller.alterarSenha(request, "Bearer token");

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(resetSenhaService).alterarSenha("Bearer token", "senhaAtual", "novaSenha");
    }
}
