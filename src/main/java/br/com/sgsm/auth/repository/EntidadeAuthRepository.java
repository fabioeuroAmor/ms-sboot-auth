package br.com.sgsm.auth.repository;

import br.com.sgsm.auth.domain.EntidadeAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface EntidadeAuthRepository extends JpaRepository<EntidadeAuth, UUID> {

    Optional<EntidadeAuth> findByReferenciaIdAndTipo(UUID referenciaId, String tipo);

    Optional<EntidadeAuth> findByEmailAndTipo(String email, String tipo);
}
