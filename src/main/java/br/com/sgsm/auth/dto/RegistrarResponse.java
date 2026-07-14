package br.com.sgsm.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class RegistrarResponse {
    private UUID id;
    private String email;
    private String tipoPerfil;
    private UUID referenciaId;
    private OffsetDateTime criadoEm;
}
