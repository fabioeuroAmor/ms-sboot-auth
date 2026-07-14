package br.com.sgsm.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class MeResponse {
    private UUID id;
    private String email;
    private String nome;
    private String perfil;
    private UUID referenciaId;
    private List<String> roles;
    private List<String> permissions;
}
