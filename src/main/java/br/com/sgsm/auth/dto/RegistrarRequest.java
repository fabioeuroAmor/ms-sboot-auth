package br.com.sgsm.auth.dto;

import java.util.UUID;

public record RegistrarRequest(
        String email,
        String senha,
        String tipoPerfil,
        UUID referenciaId
) {}
