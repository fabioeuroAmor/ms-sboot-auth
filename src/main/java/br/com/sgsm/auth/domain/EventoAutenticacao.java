package br.com.sgsm.auth.domain;

public enum EventoAutenticacao {
    LOGIN_SUCESSO,
    LOGIN_FALHA,
    LOGOUT,
    REFRESH_SUCESSO,
    REFRESH_FALHA,
    REUSO_TOKEN_REVOGADO,
    REGISTRO
}
