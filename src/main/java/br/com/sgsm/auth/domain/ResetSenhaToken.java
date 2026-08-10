package br.com.sgsm.auth.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "reset_senha_token", schema = "auth")
public class ResetSenhaToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "usuario_id", nullable = false)
    private Usuario usuario;

    @Column(nullable = false, unique = true, length = 64)
    private String token;

    @Column(name = "expira_em", nullable = false)
    private OffsetDateTime expiraEm;

    @Column(nullable = false)
    private Boolean usado;

    @Column(name = "criado_em", nullable = false, updatable = false)
    private OffsetDateTime criadoEm;

    public ResetSenhaToken() {}

    @PrePersist
    void prePersist() {
        this.usado = false;
        this.criadoEm = OffsetDateTime.now();
    }

    public UUID getId() { return id; }
    public Usuario getUsuario() { return usuario; }
    public String getToken() { return token; }
    public OffsetDateTime getExpiraEm() { return expiraEm; }
    public Boolean getUsado() { return usado; }
    public OffsetDateTime getCriadoEm() { return criadoEm; }

    public void setUsuario(Usuario usuario) { this.usuario = usuario; }
    public void setToken(String token) { this.token = token; }
    public void setExpiraEm(OffsetDateTime expiraEm) { this.expiraEm = expiraEm; }
    public void setUsado(Boolean usado) { this.usado = usado; }
}
