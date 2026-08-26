package br.com.sgsm.auth.service;

import br.com.sgsm.auth.domain.EventoAutenticacao;
import br.com.sgsm.auth.domain.LogAutenticacao;
import br.com.sgsm.auth.repository.LogAutenticacaoRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AutenticacaoAuditoriaServiceTest {

    @Mock
    private LogAutenticacaoRepository repository;

    private AutenticacaoAuditoriaService service;

    @BeforeEach
    void setUp() {
        service = new AutenticacaoAuditoriaService(repository);
    }

    @Test
    void deveRegistrarLogComTodosOsCampos() {
        UUID usuarioId = UUID.randomUUID();

        service.registrar(usuarioId, "usuario@teste.com", EventoAutenticacao.LOGIN_SUCESSO, "detalhe qualquer");

        var captor = ArgumentCaptor.forClass(LogAutenticacao.class);
        verify(repository).save(captor.capture());
        var log = captor.getValue();
        assertThat(log.getUsuarioId()).isEqualTo(usuarioId);
        assertThat(log.getEmail()).isEqualTo("usuario@teste.com");
        assertThat(log.getEvento()).isEqualTo(EventoAutenticacao.LOGIN_SUCESSO);
        assertThat(log.getDetalhe()).isEqualTo("detalhe qualquer");
    }

    @Test
    void deveRegistrarLogSemUsuarioIdQuandoDesconhecido() {
        service.registrar(null, "desconhecido@teste.com", EventoAutenticacao.LOGIN_FALHA, "email nao cadastrado");

        var captor = ArgumentCaptor.forClass(LogAutenticacao.class);
        verify(repository).save(captor.capture());
        var log = captor.getValue();
        assertThat(log.getUsuarioId()).isNull();
        assertThat(log.getEmail()).isEqualTo("desconhecido@teste.com");
        assertThat(log.getEvento()).isEqualTo(EventoAutenticacao.LOGIN_FALHA);
    }
}
