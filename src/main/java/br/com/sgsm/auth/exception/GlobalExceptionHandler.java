package br.com.sgsm.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CredenciaisInvalidasException.class)
    public ResponseEntity<ProblemDetail> handleCredenciaisInvalidas(CredenciaisInvalidasException ex, HttpServletRequest request) {
        return problem(HttpStatus.UNAUTHORIZED, "credenciais-invalidas", "Credenciais inválidas", ex.getMessage(), request);
    }

    @ExceptionHandler(TokenInvalidoException.class)
    public ResponseEntity<ProblemDetail> handleTokenInvalido(TokenInvalidoException ex, HttpServletRequest request) {
        return problem(HttpStatus.UNAUTHORIZED, "token-invalido", "Token inválido ou expirado", ex.getMessage(), request);
    }

    @ExceptionHandler(UsuarioJaExisteException.class)
    public ResponseEntity<ProblemDetail> handleUsuarioJaExiste(UsuarioJaExisteException ex, HttpServletRequest request) {
        return problem(HttpStatus.CONFLICT, "usuario-ja-existe", "Usuário já cadastrado", ex.getMessage(), request);
    }

    @ExceptionHandler(EntidadeNaoEncontradaException.class)
    public ResponseEntity<ProblemDetail> handleEntidadeNaoEncontrada(EntidadeNaoEncontradaException ex, HttpServletRequest request) {
        return problem(HttpStatus.NOT_FOUND, "entidade-nao-encontrada", "Entidade não encontrada", ex.getMessage(), request);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleArgumentoInvalido(IllegalArgumentException ex, HttpServletRequest request) {
        return problem(HttpStatus.BAD_REQUEST, "argumento-invalido", "Requisição inválida", ex.getMessage(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleErroInterno(Exception ex, HttpServletRequest request) {
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "erro-interno", "Erro interno",
                "Erro interno. Tente novamente mais tarde.", request);
    }

    private ResponseEntity<ProblemDetail> problem(HttpStatus status, String tipo, String title,
                                                   String detail, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setType(URI.create("https://sgsm.com.br/erros/" + tipo));
        pd.setTitle(title);
        pd.setInstance(URI.create(request.getRequestURI()));
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(pd);
    }
}
