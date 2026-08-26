package br.com.sgsm.auth.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "log_autenticacao", schema = "auth")
public class LogAutenticacao {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Sem @ManyToOne proposital: o evento pode se referir a um e-mail que nao tem
    // Usuario correspondente (ex.: tentativa de login com e-mail inexistente), e o
    // registro de auditoria precisa sobreviver mesmo que o Usuario seja removido depois.
    @Column(name = "usuario_id")
    private UUID usuarioId;

    @Column(length = 255)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private EventoAutenticacao evento;

    @Column(length = 255)
    private String detalhe;

    @Column(name = "criado_em", nullable = false, updatable = false)
    private OffsetDateTime criadoEm;

    public LogAutenticacao() {}

    @PrePersist
    void prePersist() {
        this.criadoEm = OffsetDateTime.now();
    }

    public UUID getId() { return id; }
    public UUID getUsuarioId() { return usuarioId; }
    public String getEmail() { return email; }
    public EventoAutenticacao getEvento() { return evento; }
    public String getDetalhe() { return detalhe; }
    public OffsetDateTime getCriadoEm() { return criadoEm; }

    public void setUsuarioId(UUID usuarioId) { this.usuarioId = usuarioId; }
    public void setEmail(String email) { this.email = email; }
    public void setEvento(EventoAutenticacao evento) { this.evento = evento; }
    public void setDetalhe(String detalhe) { this.detalhe = detalhe; }
}
