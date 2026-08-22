package br.com.sgsm.auth.service;

import br.com.sgsm.auth.domain.ResetSenhaToken;
import br.com.sgsm.auth.exception.CredenciaisInvalidasException;
import br.com.sgsm.auth.exception.TokenInvalidoException;
import br.com.sgsm.auth.exception.TokenResetInvalidoException;
import br.com.sgsm.auth.repository.EntidadeAuthRepository;
import br.com.sgsm.auth.repository.RefreshTokenRepository;
import br.com.sgsm.auth.repository.ResetSenhaTokenRepository;
import br.com.sgsm.auth.repository.UsuarioRepository;
import io.jsonwebtoken.Claims;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.UUID;

@Service
@Transactional
public class ResetSenhaService {

    private final UsuarioRepository usuarioRepository;
    private final ResetSenhaTokenRepository resetTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final EntidadeAuthRepository entidadeAuthRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final JwtService jwtService;

    public ResetSenhaService(
            UsuarioRepository usuarioRepository,
            ResetSenhaTokenRepository resetTokenRepository,
            RefreshTokenRepository refreshTokenRepository,
            EntidadeAuthRepository entidadeAuthRepository,
            PasswordEncoder passwordEncoder,
            EmailService emailService,
            JwtService jwtService) {
        this.usuarioRepository = usuarioRepository;
        this.resetTokenRepository = resetTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.entidadeAuthRepository = entidadeAuthRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.jwtService = jwtService;
    }

    public void solicitarReset(String email) {
        usuarioRepository.findByEmail(email).ifPresent(usuario -> {
            String token = UUID.randomUUID().toString().replace("-", "");
            var rt = new ResetSenhaToken();
            rt.setUsuario(usuario);
            rt.setToken(token);
            rt.setExpiraEm(OffsetDateTime.now().plusHours(2));
            resetTokenRepository.save(rt);

            String nome = resolverNome(usuario.getReferenciaId(), usuario.getTipoPerfil(), email);
            emailService.enviarLinkResetSenha(email, nome, token);
        });
    }

    public void resetarSenha(String token, String novaSenha) {
        if (novaSenha == null || novaSenha.length() < 8) {
            throw new IllegalArgumentException("A senha deve ter no mínimo 8 caracteres.");
        }

        var resetToken = resetTokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenResetInvalidoException("Link inválido."));

        if (Boolean.TRUE.equals(resetToken.getUsado())) {
            throw new TokenResetInvalidoException("Este link já foi utilizado.");
        }
        if (resetToken.getExpiraEm().isBefore(OffsetDateTime.now())) {
            throw new TokenResetInvalidoException("Link expirado. Solicite um novo.");
        }

        var usuario = resetToken.getUsuario();
        usuario.setSenhaHash(passwordEncoder.encode(novaSenha));
        usuarioRepository.save(usuario);

        resetToken.setUsado(true);
        resetTokenRepository.save(resetToken);

        refreshTokenRepository.revogarTodosPorUsuario(usuario.getId());

        String nome = resolverNome(usuario.getReferenciaId(), usuario.getTipoPerfil(), usuario.getEmail());
        emailService.enviarConfirmacaoReset(usuario.getEmail(), nome);
    }

    public void alterarSenha(String bearerToken, String senhaAtual, String novaSenha) {
        if (novaSenha == null || novaSenha.length() < 8) {
            throw new IllegalArgumentException("A senha deve ter no mínimo 8 caracteres.");
        }

        Claims claims = jwtService.extrairClaims(bearerToken.replace("Bearer ", ""));
        var usuario = usuarioRepository.findById(UUID.fromString(claims.getSubject()))
                .orElseThrow(() -> new TokenInvalidoException("Token inválido."));

        if (!passwordEncoder.matches(senhaAtual, usuario.getSenhaHash())) {
            throw new CredenciaisInvalidasException("Senha atual incorreta.");
        }

        usuario.setSenhaHash(passwordEncoder.encode(novaSenha));
        usuarioRepository.save(usuario);
    }

    private String resolverNome(UUID referenciaId, String tipoPerfil, String emailFallback) {
        if (referenciaId == null || tipoPerfil == null) return emailFallback;
        return entidadeAuthRepository
                .findByReferenciaIdAndTipo(referenciaId, tipoPerfil)
                .map(e -> e.getNome())
                .orElse(emailFallback);
    }
}
