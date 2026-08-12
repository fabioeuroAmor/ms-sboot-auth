package br.com.sgsm.auth.controller;

import br.com.sgsm.auth.dto.LoginResponse;
import br.com.sgsm.auth.dto.OtpGerarRequest;
import br.com.sgsm.auth.dto.OtpGerarResponse;
import br.com.sgsm.auth.dto.OtpVerificarRequest;
import br.com.sgsm.auth.service.OtpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OtpControllerTest {

    @Mock
    private OtpService otpService;

    private OtpController controller;

    @BeforeEach
    void setUp() {
        controller = new OtpController(otpService);
    }

    @Test
    void gerar_deveRetornarOkComCorpoDoService() {
        var request = new OtpGerarRequest("a@a.com");
        var esperado = new OtpGerarResponse("123456", 300L);
        when(otpService.gerar("a@a.com")).thenReturn(esperado);

        var resposta = controller.gerar(request);

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resposta.getBody()).isSameAs(esperado);
    }

    @Test
    void verificar_deveRetornarOkComCorpoDoService() {
        var request = new OtpVerificarRequest("a@a.com", "123456");
        var esperado = new LoginResponse("access", "refresh", 900L);
        when(otpService.verificar("a@a.com", "123456")).thenReturn(esperado);

        var resposta = controller.verificar(request);

        assertThat(resposta.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resposta.getBody()).isSameAs(esperado);
    }
}
