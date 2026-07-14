package br.com.sgsm.auth.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.Immutable;
import java.util.UUID;

/**
 * Projecao somente-leitura da view auth.v_entidades_possiveis.
 * Usada para validar se referenciaId existe e esta ativo em sgsm.*.
 */
@Entity
@Immutable
@Table(name = "v_entidades_possiveis", schema = "auth")
public class EntidadeAuth {

    @Id
    @Column(name = "referencia_id")
    private UUID referenciaId;

    @Column
    private String email;

    @Column
    private String nome;

    @Column
    private Boolean ativo;

    @Column
    private String tipo;

    public EntidadeAuth() {}

    public UUID getReferenciaId() { return referenciaId; }
    public String getEmail() { return email; }
    public String getNome() { return nome; }
    public Boolean getAtivo() { return ativo; }
    public String getTipo() { return tipo; }
}
