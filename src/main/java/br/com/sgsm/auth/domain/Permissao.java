package br.com.sgsm.auth.domain;

import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "permissao", schema = "ms-sboot-auth")
public class Permissao {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 200)
    private String nome;

    @Column(nullable = false, length = 100)
    private String recurso;

    @Column(nullable = false, length = 50)
    private String acao;

    @Column
    private String descricao;

    public Permissao() {}

    public UUID getId() { return id; }
    public String getNome() { return nome; }
    public String getRecurso() { return recurso; }
    public String getAcao() { return acao; }
    public String getDescricao() { return descricao; }

    public void setNome(String nome) { this.nome = nome; }
    public void setRecurso(String recurso) { this.recurso = recurso; }
    public void setAcao(String acao) { this.acao = acao; }
    public void setDescricao(String descricao) { this.descricao = descricao; }
}
