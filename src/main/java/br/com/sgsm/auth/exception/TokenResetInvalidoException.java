package br.com.sgsm.auth.exception;

public class TokenResetInvalidoException extends RuntimeException {
    public TokenResetInvalidoException(String message) {
        super(message);
    }
}
