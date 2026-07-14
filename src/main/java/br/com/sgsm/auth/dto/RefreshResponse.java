package br.com.sgsm.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class RefreshResponse {
    private String accessToken;
    private long expiresIn;
    private String tipo = "Bearer";

    public RefreshResponse(String accessToken, long expiresIn) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.tipo = "Bearer";
    }
}
