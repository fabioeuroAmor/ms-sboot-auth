package br.com.sgsm.auth.repository;

import br.com.sgsm.auth.domain.LogAutenticacao;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface LogAutenticacaoRepository extends JpaRepository<LogAutenticacao, UUID> {
}
