package br.com.sgsm.auth.repository;

import br.com.sgsm.auth.domain.ResetSenhaToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface ResetSenhaTokenRepository extends JpaRepository<ResetSenhaToken, UUID> {

    Optional<ResetSenhaToken> findByToken(String token);
}
