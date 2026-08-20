package br.com.sgsm.auth.service;

import br.com.sgsm.auth.domain.EntidadeAuth;
import br.com.sgsm.auth.domain.ResetSenhaToken;
import br.com.sgsm.auth.domain.Usuario;
import br.com.sgsm.auth.exception.CredenciaisInvalidasException;
import br.com.sgsm.auth.exception.TokenInvalidoException;
import br.com.sgsm.auth.exception.TokenResetInvalidoException;
import br.com.sgsm.auth.repository.EntidadeAuthRepository;
import br.com.sgsm.auth.repository.RefreshTokenRepository;
import br.com.sgsm.auth.repository.ResetSenhaTokenRepository;
import br.com.sgsm.auth.repository.UsuarioRepository;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ResetSenhaServiceTest {

    @Mock
    private UsuarioRepository usuarioRepository;
    @Mock
    private ResetSenhaTokenRepository resetTokenRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private EntidadeAuthRepository entidadeAuthRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private EmailService emailService;
    @Mock
    private JwtService jwtService;

    private ResetSenhaService service;

    private final UUID referenciaId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        service = new ResetSenhaService(usuarioRepository, resetTokenRepository, refreshTokenRepository,
                entidadeAuthRepository, passwordEncoder, emailService, jwtService);
    }

    private Usuario usuario(String email, UUID id) {
        Usuario usuario = new Usuario();
        ReflectionTestUtils.setField(usuario, "id", id);
        usuario.setEmail(email);
        usuario.setSenhaHash("hash-antigo");
        usuario.setTipoPerfil("PACIENTE");
        usuario.setReferenciaId(referenciaId);
        return usuario;
    }

    private EntidadeAuth entidadeComNome(String nome) {
        EntidadeAuth entidade = new EntidadeAuth();
        ReflectionTestUtils.setField(entidade, "nome", nome);
        return entidade;
    }

    // ---------- solicitarReset ----------

    @Test
    void solicitarReset_naoDeveFazerNada_quandoUsuarioNaoExiste() {
        when(usuarioRepository.findByEmail("naoexiste@a.com")).thenReturn(Optional.empty());

        service.solicitarReset("naoexiste@a.com");

        verify(resetTokenRepository, never()).save(any());
        verify(emailService, never()).enviarLinkResetSenha(any(), any(), any());
    }

    @Test
    void solicitarReset_deveGerarTokenEEnviarEmail_quandoUsuarioExiste() {
        Usuario usuario = usuario("a@a.com", UUID.randomUUID());
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidadeComNome("Nome Teste")));

        service.solicitarReset("a@a.com");

        ArgumentCaptor<ResetSenhaToken> captor = ArgumentCaptor.forClass(ResetSenhaToken.class);
        verify(resetTokenRepository).save(captor.capture());
        assertThat(captor.getValue().getUsuario()).isEqualTo(usuario);
        assertThat(captor.getValue().getToken()).isNotBlank();
        assertThat(captor.getValue().getExpiraEm()).isAfter(OffsetDateTime.now());

        verify(emailService).enviarLinkResetSenha(eq("a@a.com"), eq("Nome Teste"), eq(captor.getValue().getToken()));
    }

    @Test
    void solicitarReset_deveUsarEmailComoNome_quandoEntidadeNaoEncontrada() {
        Usuario usuario = usuario("a@a.com", UUID.randomUUID());
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.empty());

        service.solicitarReset("a@a.com");

        verify(emailService).enviarLinkResetSenha(eq("a@a.com"), eq("a@a.com"), any());
    }

    // ---------- resetarSenha ----------

    @Test
    void resetarSenha_deveLancarTokenResetInvalido_quandoTokenNaoExiste() {
        when(resetTokenRepository.findByToken("inexistente")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.resetarSenha("inexistente", "novaSenha"))
                .isInstanceOf(TokenResetInvalidoException.class)
                .hasMessageContaining("inválido");
    }

    @Test
    void resetarSenha_deveLancarTokenResetInvalido_quandoTokenJaUsado() {
        ResetSenhaToken rt = new ResetSenhaToken();
        rt.setUsado(true);
        when(resetTokenRepository.findByToken("token")).thenReturn(Optional.of(rt));

        assertThatThrownBy(() -> service.resetarSenha("token", "novaSenha"))
                .isInstanceOf(TokenResetInvalidoException.class)
                .hasMessageContaining("já foi utilizado");
    }

    @Test
    void resetarSenha_deveLancarTokenResetInvalido_quandoTokenExpirado() {
        ResetSenhaToken rt = new ResetSenhaToken();
        rt.setUsado(false);
        rt.setExpiraEm(OffsetDateTime.now().minusHours(1));
        when(resetTokenRepository.findByToken("token")).thenReturn(Optional.of(rt));

        assertThatThrownBy(() -> service.resetarSenha("token", "novaSenha"))
                .isInstanceOf(TokenResetInvalidoException.class)
                .hasMessageContaining("expirado");
    }

    @Test
    void resetarSenha_deveLancarIllegalArgument_quandoSenhaCurta() {
        assertThatThrownBy(() -> service.resetarSenha("token", "curta"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("8 caracteres");
        verify(resetTokenRepository, never()).findByToken(any());
    }

    @Test
    void resetarSenha_deveAlterarSenhaERevogarRefreshTokens_quandoTokenValido() {
        UUID usuarioId = UUID.randomUUID();
        Usuario usuario = usuario("a@a.com", usuarioId);
        ResetSenhaToken rt = new ResetSenhaToken();
        rt.setUsuario(usuario);
        rt.setUsado(false);
        rt.setExpiraEm(OffsetDateTime.now().plusHours(1));
        when(resetTokenRepository.findByToken("token")).thenReturn(Optional.of(rt));
        when(passwordEncoder.encode("novaSenha")).thenReturn("novo-hash");
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidadeComNome("Nome Teste")));

        service.resetarSenha("token", "novaSenha");

        assertThat(usuario.getSenhaHash()).isEqualTo("novo-hash");
        verify(usuarioRepository).save(usuario);
        assertThat(rt.getUsado()).isTrue();
        verify(resetTokenRepository).save(rt);
        verify(refreshTokenRepository).revogarTodosPorUsuario(usuarioId);
        verify(emailService).enviarConfirmacaoReset("a@a.com", "Nome Teste");
    }

    // ---------- alterarSenha ----------

    @Test
    void alterarSenha_deveLancarIllegalArgument_quandoSenhaCurta() {
        assertThatThrownBy(() -> service.alterarSenha("Bearer token-valido", "atual", "curta"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("8 caracteres");
        verify(jwtService, never()).extrairClaims(any());
    }

    @Test
    void alterarSenha_deveLancarTokenInvalido_quandoUsuarioNaoExiste() {
        UUID usuarioId = UUID.randomUUID();
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(usuarioId.toString());
        when(jwtService.extrairClaims("token-valido")).thenReturn(claims);
        when(usuarioRepository.findById(usuarioId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.alterarSenha("Bearer token-valido", "atual", "novaSenha"))
                .isInstanceOf(TokenInvalidoException.class);
    }

    @Test
    void alterarSenha_deveLancarCredenciaisInvalidas_quandoSenhaAtualIncorreta() {
        UUID usuarioId = UUID.randomUUID();
        Usuario usuario = usuario("a@a.com", usuarioId);
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(usuarioId.toString());
        when(jwtService.extrairClaims("token-valido")).thenReturn(claims);
        when(usuarioRepository.findById(usuarioId)).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senhaErrada", "hash-antigo")).thenReturn(false);

        assertThatThrownBy(() -> service.alterarSenha("Bearer token-valido", "senhaErrada", "novaSenha"))
                .isInstanceOf(CredenciaisInvalidasException.class)
                .hasMessageContaining("incorreta");
    }

    @Test
    void alterarSenha_deveAlterarSenha_quandoSenhaAtualCorreta() {
        UUID usuarioId = UUID.randomUUID();
        Usuario usuario = usuario("a@a.com", usuarioId);
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(usuarioId.toString());
        when(jwtService.extrairClaims("token-valido")).thenReturn(claims);
        when(usuarioRepository.findById(usuarioId)).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senhaAtual", "hash-antigo")).thenReturn(true);
        when(passwordEncoder.encode("novaSenha")).thenReturn("novo-hash");

        service.alterarSenha("Bearer token-valido", "senhaAtual", "novaSenha");

        assertThat(usuario.getSenhaHash()).isEqualTo("novo-hash");
        verify(usuarioRepository).save(usuario);
    }
}
