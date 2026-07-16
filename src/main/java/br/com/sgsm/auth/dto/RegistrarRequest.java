package br.com.sgsm.auth.dto;

import java.util.UUID;

public record RegistrarRequest(
        String email,
        String senha,
        String tipoPerfil,
        UUID referenciaId
) {
    @Override
    public String toString() {
        return "RegistrarRequest[email=" + email + ", senha=****, tipoPerfil=" + tipoPerfil
                + ", referenciaId=" + referenciaId + "]";
    }
}
