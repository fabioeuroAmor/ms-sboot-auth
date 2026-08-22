package br.com.sgsm.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
    private String tipo = "Bearer";
    private String tipoPerfil;

    public LoginResponse(String accessToken, String refreshToken, long expiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.tipo = "Bearer";
    }
}
