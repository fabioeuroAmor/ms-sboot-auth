package br.com.sgsm.auth.service;

import br.com.sgsm.auth.domain.EventoAutenticacao;
import br.com.sgsm.auth.domain.LogAutenticacao;
import br.com.sgsm.auth.repository.LogAutenticacaoRepository;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AutenticacaoAuditoriaService {

    private final LogAutenticacaoRepository repository;

    public AutenticacaoAuditoriaService(LogAutenticacaoRepository repository) {
        this.repository = repository;
    }

    public void registrar(UUID usuarioId, String email, EventoAutenticacao evento, String detalhe) {
        var log = new LogAutenticacao();
        log.setUsuarioId(usuarioId);
        log.setEmail(email);
        log.setEvento(evento);
        log.setDetalhe(detalhe);
        repository.save(log);
    }
}
