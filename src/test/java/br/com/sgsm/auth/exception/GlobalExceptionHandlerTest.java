package br.com.sgsm.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/v1/api/auth/login");
    }

    private void assertProblem(ResponseEntity<ProblemDetail> resposta, HttpStatus status,
                                String tipoEsperado, String tituloEsperado, String detalheEsperado) {
        assertThat(resposta.getStatusCode()).isEqualTo(status);
        assertThat(resposta.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        ProblemDetail body = resposta.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getStatus()).isEqualTo(status.value());
        assertThat(body.getTitle()).isEqualTo(tituloEsperado);
        assertThat(body.getDetail()).isEqualTo(detalheEsperado);
        assertThat(body.getType().toString()).isEqualTo("https://sgsm.com.br/erros/" + tipoEsperado);
        assertThat(body.getInstance().toString()).isEqualTo("/v1/api/auth/login");
    }

    @Test
    void handleCredenciaisInvalidas_deveRetornar401() {
        var resposta = handler.handleCredenciaisInvalidas(
                new CredenciaisInvalidasException("Credenciais invalidas."), request);

        assertProblem(resposta, HttpStatus.UNAUTHORIZED, "credenciais-invalidas",
                "Credenciais inválidas", "Credenciais invalidas.");
    }

    @Test
    void handleTokenInvalido_deveRetornar401() {
        var resposta = handler.handleTokenInvalido(
                new TokenInvalidoException("Token invalido ou expirado."), request);

        assertProblem(resposta, HttpStatus.UNAUTHORIZED, "token-invalido",
                "Token inválido ou expirado", "Token invalido ou expirado.");
    }

    @Test
    void handleUsuarioJaExiste_deveRetornar409() {
        var resposta = handler.handleUsuarioJaExiste(
                new UsuarioJaExisteException("Email ja cadastrado: a@a.com"), request);

        assertProblem(resposta, HttpStatus.CONFLICT, "usuario-ja-existe",
                "Usuário já cadastrado", "Email ja cadastrado: a@a.com");
    }

    @Test
    void handleEntidadeNaoEncontrada_deveRetornar404() {
        var resposta = handler.handleEntidadeNaoEncontrada(
                new EntidadeNaoEncontradaException("Nao encontrada."), request);

        assertProblem(resposta, HttpStatus.NOT_FOUND, "entidade-nao-encontrada",
                "Entidade não encontrada", "Nao encontrada.");
    }

    @Test
    void handleArgumentoInvalido_deveRetornar400() {
        var resposta = handler.handleArgumentoInvalido(
                new IllegalArgumentException("tipoPerfil invalido."), request);

        assertProblem(resposta, HttpStatus.BAD_REQUEST, "argumento-invalido",
                "Requisição inválida", "tipoPerfil invalido.");
    }

    @Test
    void handleErroInterno_deveRetornar500ComMensagemGenerica() {
        var resposta = handler.handleErroInterno(new RuntimeException("detalhe sensivel"), request);

        assertProblem(resposta, HttpStatus.INTERNAL_SERVER_ERROR, "erro-interno", "Erro interno",
                "Erro interno. Tente novamente mais tarde.");
    }
}
