package br.com.sgsm.auth.service;

import br.com.sgsm.auth.config.JwtProperties;
import br.com.sgsm.auth.domain.EntidadeAuth;
import br.com.sgsm.auth.domain.Permissao;
import br.com.sgsm.auth.domain.RefreshToken;
import br.com.sgsm.auth.domain.Role;
import br.com.sgsm.auth.domain.Usuario;
import br.com.sgsm.auth.dto.LoginRequest;
import br.com.sgsm.auth.dto.LogoutRequest;
import br.com.sgsm.auth.dto.RefreshRequest;
import br.com.sgsm.auth.dto.RegistrarRequest;
import br.com.sgsm.auth.exception.CredenciaisInvalidasException;
import br.com.sgsm.auth.exception.EntidadeNaoEncontradaException;
import br.com.sgsm.auth.exception.TokenInvalidoException;
import br.com.sgsm.auth.exception.UsuarioJaExisteException;
import br.com.sgsm.auth.repository.EntidadeAuthRepository;
import br.com.sgsm.auth.repository.RefreshTokenRepository;
import br.com.sgsm.auth.repository.RoleRepository;
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
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UsuarioRepository usuarioRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private EntidadeAuthRepository entidadeAuthRepository;
    @Mock
    private JwtService jwtService;
    @Mock
    private JwtBlacklistService jwtBlacklistService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private EmailService emailService;

    private AuthService service;

    private final UUID referenciaId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        JwtProperties jwtProperties = new JwtProperties("secret", 15, 7);
        service = new AuthService(usuarioRepository, roleRepository, refreshTokenRepository,
                entidadeAuthRepository, jwtService, jwtBlacklistService, passwordEncoder, jwtProperties,
                emailService);
    }

    private EntidadeAuth entidadeAtiva(String email, String tipo) {
        EntidadeAuth entidade = new EntidadeAuth();
        ReflectionTestUtils.setField(entidade, "referenciaId", referenciaId);
        ReflectionTestUtils.setField(entidade, "email", email);
        ReflectionTestUtils.setField(entidade, "nome", "Nome Teste");
        ReflectionTestUtils.setField(entidade, "ativo", true);
        ReflectionTestUtils.setField(entidade, "tipo", tipo);
        return entidade;
    }

    private Role role(String nome, Permissao... permissoes) {
        Role role = new Role();
        role.setNome(nome);
        role.setPermissoes(Set.of(permissoes));
        return role;
    }

    private Permissao permissao(String nome) {
        Permissao permissao = new Permissao();
        permissao.setNome(nome);
        return permissao;
    }

    private Usuario usuarioAtivo(String email, String senhaHash, String tipoPerfil, Role... roles) {
        Usuario usuario = new Usuario();
        ReflectionTestUtils.setField(usuario, "id", UUID.randomUUID());
        usuario.setEmail(email);
        usuario.setSenhaHash(senhaHash);
        usuario.setTipoPerfil(tipoPerfil);
        usuario.setReferenciaId(referenciaId);
        usuario.setAtivo(true);
        usuario.setRoles(Set.of(roles));
        return usuario;
    }

    // ---------- emailDisponivel ----------

    @Test
    void emailDisponivel_deveRetornarTrue_quandoEmailNaoCadastrado() {
        when(usuarioRepository.existsByEmail("livre@a.com")).thenReturn(false);

        assertThat(service.emailDisponivel("livre@a.com")).isTrue();
    }

    @Test
    void emailDisponivel_deveRetornarFalse_quandoEmailJaCadastrado() {
        when(usuarioRepository.existsByEmail("ocupado@a.com")).thenReturn(true);

        assertThat(service.emailDisponivel("ocupado@a.com")).isFalse();
    }

    // ---------- registrar ----------

    @Test
    void registrar_deveLancarIllegalArgument_quandoTipoPerfilInvalido() {
        var request = new RegistrarRequest("a@a.com", "senha123", "INVALIDO", referenciaId);

        assertThatThrownBy(() -> service.registrar(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("tipoPerfil invalido");
    }

    @Test
    void registrar_deveLancarEntidadeNaoEncontrada_quandoEntidadeNaoExiste() {
        var request = new RegistrarRequest("a@a.com", "senha123", "PACIENTE", referenciaId);
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.registrar(request))
                .isInstanceOf(EntidadeNaoEncontradaException.class)
                .hasMessageContaining("Nenhum registro ativo encontrado");
    }

    @Test
    void registrar_deveLancarEntidadeNaoEncontrada_quandoEntidadeInativa() {
        var request = new RegistrarRequest("a@a.com", "senha123", "PACIENTE", referenciaId);
        EntidadeAuth entidade = entidadeAtiva("a@a.com", "PACIENTE");
        ReflectionTestUtils.setField(entidade, "ativo", false);
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidade));

        assertThatThrownBy(() -> service.registrar(request))
                .isInstanceOf(EntidadeNaoEncontradaException.class)
                .hasMessageContaining("inativa");
    }

    @Test
    void registrar_deveLancarCredenciaisInvalidas_quandoEmailNaoCorresponde() {
        var request = new RegistrarRequest("outro@a.com", "senha123", "PACIENTE", referenciaId);
        EntidadeAuth entidade = entidadeAtiva("a@a.com", "PACIENTE");
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidade));

        assertThatThrownBy(() -> service.registrar(request))
                .isInstanceOf(CredenciaisInvalidasException.class)
                .hasMessageContaining("nao corresponde");
    }

    @Test
    void registrar_deveLancarUsuarioJaExiste_quandoEmailJaCadastrado() {
        var request = new RegistrarRequest("a@a.com", "senha123", "PACIENTE", referenciaId);
        EntidadeAuth entidade = entidadeAtiva("a@a.com", "PACIENTE");
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidade));
        when(usuarioRepository.existsByEmail("a@a.com")).thenReturn(true);

        assertThatThrownBy(() -> service.registrar(request))
                .isInstanceOf(UsuarioJaExisteException.class)
                .hasMessageContaining("Email ja cadastrado");
    }

    @Test
    void registrar_deveLancarEntidadeNaoEncontrada_quandoRoleNaoExiste() {
        var request = new RegistrarRequest("a@a.com", "senha123", "PACIENTE", referenciaId);
        EntidadeAuth entidade = entidadeAtiva("a@a.com", "PACIENTE");
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidade));
        when(usuarioRepository.existsByEmail("a@a.com")).thenReturn(false);
        when(roleRepository.findByNome("PACIENTE")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.registrar(request))
                .isInstanceOf(EntidadeNaoEncontradaException.class)
                .hasMessageContaining("Role nao encontrada");
    }

    @Test
    void registrar_deveCriarUsuario_quandoDadosValidos() {
        var request = new RegistrarRequest("a@a.com", "senha123", "PACIENTE", referenciaId);
        EntidadeAuth entidade = entidadeAtiva("a@a.com", "PACIENTE");
        Role role = role("PACIENTE");
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidade));
        when(usuarioRepository.existsByEmail("a@a.com")).thenReturn(false);
        when(roleRepository.findByNome("PACIENTE")).thenReturn(Optional.of(role));
        when(passwordEncoder.encode("senha123")).thenReturn("hash-senha");

        UUID novoId = UUID.randomUUID();
        OffsetDateTime criadoEm = OffsetDateTime.now();
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(invocation -> {
            Usuario usuario = invocation.getArgument(0);
            ReflectionTestUtils.setField(usuario, "id", novoId);
            ReflectionTestUtils.setField(usuario, "criadoEm", criadoEm);
            return usuario;
        });

        var response = service.registrar(request);

        assertThat(response.getId()).isEqualTo(novoId);
        assertThat(response.getEmail()).isEqualTo("a@a.com");
        assertThat(response.getTipoPerfil()).isEqualTo("PACIENTE");
        assertThat(response.getReferenciaId()).isEqualTo(referenciaId);
        assertThat(response.getCriadoEm()).isEqualTo(criadoEm);

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(captor.capture());
        assertThat(captor.getValue().getSenhaHash()).isEqualTo("hash-senha");
        assertThat(captor.getValue().getRoles()).containsExactly(role);

        verify(emailService).enviarBoasVindas("a@a.com", "Nome Teste", "PACIENTE", "senha123");
    }

    @Test
    void registrar_deveResolverEntidadePeloEmail_quandoFuncionarioSemReferenciaId() {
        var request = new RegistrarRequest("func@a.com", "senha123", "FUNCIONARIO", null);
        EntidadeAuth entidade = entidadeAtiva("func@a.com", "FUNCIONARIO");
        Role role = role("FUNCIONARIO");
        when(entidadeAuthRepository.findByEmailAndTipo("func@a.com", "FUNCIONARIO"))
                .thenReturn(Optional.of(entidade));
        when(usuarioRepository.existsByEmail("func@a.com")).thenReturn(false);
        when(roleRepository.findByNome("FUNCIONARIO")).thenReturn(Optional.of(role));
        when(passwordEncoder.encode("senha123")).thenReturn("hash-senha");
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.registrar(request);

        assertThat(response.getReferenciaId()).isEqualTo(referenciaId);
        verify(entidadeAuthRepository).findByEmailAndTipo("func@a.com", "FUNCIONARIO");
        verify(entidadeAuthRepository, never()).findByReferenciaIdAndTipo(any(), any());
    }

    @Test
    void registrar_deveCriarDesenvolvedor_quandoDadosValidos() {
        var request = new RegistrarRequest("dev@a.com", "senha123", "DESENVOLVEDOR", null);
        Role role = role("DESENVOLVEDOR");
        when(usuarioRepository.existsByEmail("dev@a.com")).thenReturn(false);
        when(roleRepository.findByNome("DESENVOLVEDOR")).thenReturn(Optional.of(role));
        when(passwordEncoder.encode("senha123")).thenReturn("hash-senha");

        UUID novoId = UUID.randomUUID();
        OffsetDateTime criadoEm = OffsetDateTime.now();
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(invocation -> {
            Usuario usuario = invocation.getArgument(0);
            ReflectionTestUtils.setField(usuario, "id", novoId);
            ReflectionTestUtils.setField(usuario, "criadoEm", criadoEm);
            return usuario;
        });

        var response = service.registrar(request);

        assertThat(response.getId()).isEqualTo(novoId);
        assertThat(response.getEmail()).isEqualTo("dev@a.com");
        assertThat(response.getTipoPerfil()).isEqualTo("DESENVOLVEDOR");
        assertThat(response.getReferenciaId()).isNull();
        assertThat(response.getCriadoEm()).isEqualTo(criadoEm);

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(captor.capture());
        assertThat(captor.getValue().getSenhaHash()).isEqualTo("hash-senha");
        assertThat(captor.getValue().getReferenciaId()).isNull();
        assertThat(captor.getValue().getRoles()).containsExactly(role);

        verify(entidadeAuthRepository, never()).findByReferenciaIdAndTipo(any(), any());
        verify(emailService, never()).enviarBoasVindas(any(), any(), any(), any());
    }

    @Test
    void registrar_deveLancarUsuarioJaExiste_quandoDesenvolvedorComEmailDuplicado() {
        var request = new RegistrarRequest("dev@a.com", "senha123", "DESENVOLVEDOR", null);
        when(usuarioRepository.existsByEmail("dev@a.com")).thenReturn(true);

        assertThatThrownBy(() -> service.registrar(request))
                .isInstanceOf(UsuarioJaExisteException.class)
                .hasMessageContaining("Email ja cadastrado");

        verify(roleRepository, never()).findByNome(any());
    }

    @Test
    void registrar_deveLancarEntidadeNaoEncontrada_quandoRoleDesenvolvedorNaoExiste() {
        var request = new RegistrarRequest("dev@a.com", "senha123", "DESENVOLVEDOR", null);
        when(usuarioRepository.existsByEmail("dev@a.com")).thenReturn(false);
        when(roleRepository.findByNome("DESENVOLVEDOR")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.registrar(request))
                .isInstanceOf(EntidadeNaoEncontradaException.class)
                .hasMessageContaining("Role nao encontrada: DESENVOLVEDOR");
    }

    // ---------- login ----------

    @Test
    void login_deveLancarCredenciaisInvalidas_quandoUsuarioNaoExiste() {
        var request = new LoginRequest("a@a.com", "senha123");
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login(request))
                .isInstanceOf(CredenciaisInvalidasException.class);
    }

    @Test
    void login_deveLancarCredenciaisInvalidas_quandoUsuarioInativo() {
        var request = new LoginRequest("a@a.com", "senha123");
        Usuario usuario = usuarioAtivo("a@a.com", "hash", "PACIENTE");
        usuario.setAtivo(false);
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));

        assertThatThrownBy(() -> service.login(request))
                .isInstanceOf(CredenciaisInvalidasException.class);
    }

    @Test
    void login_deveLancarCredenciaisInvalidas_quandoSenhaIncorreta() {
        var request = new LoginRequest("a@a.com", "senhaErrada");
        Usuario usuario = usuarioAtivo("a@a.com", "hash", "PACIENTE");
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senhaErrada", "hash")).thenReturn(false);

        assertThatThrownBy(() -> service.login(request))
                .isInstanceOf(CredenciaisInvalidasException.class);
    }

    @Test
    void login_deveLancarCredenciaisInvalidas_quandoEntidadeInativaOuRemovida() {
        var request = new LoginRequest("a@a.com", "senha123");
        Usuario usuario = usuarioAtivo("a@a.com", "hash", "PACIENTE");
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senha123", "hash")).thenReturn(true);
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login(request))
                .isInstanceOf(CredenciaisInvalidasException.class)
                .hasMessageContaining("inativa ou foi removida");
    }

    @Test
    void login_deveRetornarTokens_quandoCredenciaisValidas() {
        var request = new LoginRequest("a@a.com", "senha123");
        Role role = role("PACIENTE", permissao("AGENDA_LER"), permissao("AGENDA_LER"));
        Usuario usuario = usuarioAtivo("a@a.com", "hash", "PACIENTE", role);
        EntidadeAuth entidade = entidadeAtiva("a@a.com", "PACIENTE");

        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senha123", "hash")).thenReturn(true);
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidade));
        when(jwtService.gerarToken(eq(usuario.getId()), eq("a@a.com"), eq("Nome Teste"),
                eq("PACIENTE"), eq(referenciaId), anyList(), anyList()))
                .thenReturn("access-token-123");
        when(jwtService.expiracaoEmSegundos()).thenReturn(900L);

        var response = service.login(request);

        assertThat(response.getAccessToken()).isEqualTo("access-token-123");
        assertThat(response.getRefreshToken()).isNotBlank();
        assertThat(response.getExpiresIn()).isEqualTo(900L);
        assertThat(response.getTipo()).isEqualTo("Bearer");

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        assertThat(captor.getValue().getUsuario()).isEqualTo(usuario);
        assertThat(captor.getValue().getToken()).isEqualTo(response.getRefreshToken());
    }

    @Test
    void login_deveUsarEmailComoNome_quandoEntidadeSomenteAtivaNaoEncontradaNaSegundaConsulta() {
        var request = new LoginRequest("a@a.com", "senha123");
        Role role = role("PACIENTE");
        Usuario usuario = usuarioAtivo("a@a.com", "hash", "PACIENTE", role);
        EntidadeAuth entidade = entidadeAtiva("a@a.com", "PACIENTE");

        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senha123", "hash")).thenReturn(true);
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidade), Optional.empty());
        when(jwtService.gerarToken(any(), any(), any(), any(), any(), anyList(), anyList()))
                .thenReturn("token");
        when(jwtService.expiracaoEmSegundos()).thenReturn(900L);

        service.login(request);

        verify(jwtService).gerarToken(eq(usuario.getId()), eq("a@a.com"), eq("a@a.com"),
                eq("PACIENTE"), eq(referenciaId), anyList(), anyList());
    }

    // ---------- refresh ----------

    @Test
    void refresh_deveLancarTokenInvalido_quandoTokenNaoExiste() {
        var request = new RefreshRequest("token-inexistente");
        when(refreshTokenRepository.findByToken("token-inexistente")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.refresh(request))
                .isInstanceOf(TokenInvalidoException.class)
                .hasMessageContaining("invalido");
    }

    @Test
    void refresh_deveLancarTokenInvalido_quandoTokenRevogado() {
        var request = new RefreshRequest("token-revogado");
        RefreshToken rt = new RefreshToken();
        rt.setRevogado(true);
        rt.setExpiraEm(OffsetDateTime.now().plusDays(1));
        when(refreshTokenRepository.findByToken("token-revogado")).thenReturn(Optional.of(rt));

        assertThatThrownBy(() -> service.refresh(request))
                .isInstanceOf(TokenInvalidoException.class)
                .hasMessageContaining("revogado");
    }

    @Test
    void refresh_deveLancarTokenInvalido_quandoTokenExpirado() {
        var request = new RefreshRequest("token-expirado");
        RefreshToken rt = new RefreshToken();
        rt.setRevogado(false);
        rt.setExpiraEm(OffsetDateTime.now().minusDays(1));
        when(refreshTokenRepository.findByToken("token-expirado")).thenReturn(Optional.of(rt));

        assertThatThrownBy(() -> service.refresh(request))
                .isInstanceOf(TokenInvalidoException.class)
                .hasMessageContaining("expirado");
    }

    @Test
    void refresh_deveRetornarNovoToken_quandoTokenValido() {
        var request = new RefreshRequest("token-valido");
        Role role = role("MEDICO", permissao("AGENDA_ESCREVER"));
        Usuario usuario = usuarioAtivo("medico@a.com", "hash", "MEDICO", role);
        EntidadeAuth entidade = entidadeAtiva("medico@a.com", "MEDICO");

        RefreshToken rt = new RefreshToken();
        rt.setUsuario(usuario);
        rt.setRevogado(false);
        rt.setExpiraEm(OffsetDateTime.now().plusDays(1));
        when(refreshTokenRepository.findByToken("token-valido")).thenReturn(Optional.of(rt));
        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "MEDICO"))
                .thenReturn(Optional.of(entidade));
        when(jwtService.gerarToken(eq(usuario.getId()), eq("medico@a.com"), eq("Nome Teste"),
                eq("MEDICO"), eq(referenciaId), anyList(), anyList()))
                .thenReturn("novo-access-token");
        when(jwtService.expiracaoEmSegundos()).thenReturn(900L);

        var response = service.refresh(request);

        assertThat(response.getAccessToken()).isEqualTo("novo-access-token");
        assertThat(response.getRefreshToken()).isNotBlank().isNotEqualTo("token-valido");
        assertThat(response.getExpiresIn()).isEqualTo(900L);
        assertThat(response.getTipo()).isEqualTo("Bearer");

        assertThat(rt.getRevogado()).isTrue();
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository, times(2)).save(captor.capture());
        assertThat(captor.getAllValues().get(0)).isSameAs(rt);
        RefreshToken novoRt = captor.getAllValues().get(1);
        assertThat(novoRt.getToken()).isEqualTo(response.getRefreshToken());
        assertThat(novoRt.getUsuario()).isEqualTo(usuario);
    }

    // ---------- loginPorOtp ----------

    @Test
    void loginPorOtp_deveRetornarTokens_quandoUsuarioAtivo() {
        Role role = role("PACIENTE", permissao("AGENDA_LER"));
        Usuario usuario = usuarioAtivo("a@a.com", "hash", "PACIENTE", role);
        EntidadeAuth entidade = entidadeAtiva("a@a.com", "PACIENTE");

        when(entidadeAuthRepository.findByReferenciaIdAndTipo(referenciaId, "PACIENTE"))
                .thenReturn(Optional.of(entidade));
        when(jwtService.gerarToken(eq(usuario.getId()), eq("a@a.com"), eq("Nome Teste"),
                eq("PACIENTE"), eq(referenciaId), anyList(), anyList()))
                .thenReturn("access-token-otp");
        when(jwtService.expiracaoEmSegundos()).thenReturn(900L);

        var response = service.loginPorOtp(usuario);

        assertThat(response.getAccessToken()).isEqualTo("access-token-otp");
        assertThat(response.getRefreshToken()).isNotBlank();
        assertThat(response.getExpiresIn()).isEqualTo(900L);
        assertThat(response.getTipo()).isEqualTo("Bearer");
        assertThat(response.getTipoPerfil()).isEqualTo("PACIENTE");

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        assertThat(captor.getValue().getUsuario()).isEqualTo(usuario);
        assertThat(captor.getValue().getToken()).isEqualTo(response.getRefreshToken());
    }

    @Test
    void loginPorOtp_deveLancarCredenciaisInvalidas_quandoUsuarioInativo() {
        Usuario usuario = usuarioAtivo("a@a.com", "hash", "PACIENTE");
        usuario.setAtivo(false);

        assertThatThrownBy(() -> service.loginPorOtp(usuario))
                .isInstanceOf(CredenciaisInvalidasException.class)
                .hasMessageContaining("inativo");

        verify(refreshTokenRepository, never()).save(any());
    }

    // ---------- logout ----------

    @Test
    void logout_deveRevogarToken_quandoTokenExiste() {
        RefreshToken rt = new RefreshToken();
        rt.setRevogado(false);
        when(refreshTokenRepository.findByToken("token-existente")).thenReturn(Optional.of(rt));

        service.logout("token-existente", null);

        assertThat(rt.getRevogado()).isTrue();
        verify(refreshTokenRepository, times(1)).save(rt);
    }

    @Test
    void logout_naoDeveFazerNada_quandoTokenNaoExiste() {
        when(refreshTokenRepository.findByToken("token-inexistente")).thenReturn(Optional.empty());

        service.logout("token-inexistente", null);

        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void logout_deveRevogarAccessTokenNaBlacklist_quandoBearerTokenPresente() {
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.empty());

        service.logout("refresh-token", "Bearer access-token-123");

        verify(jwtBlacklistService).revogar("access-token-123");
    }

    @Test
    void logout_naoDeveRevogarNaBlacklist_quandoBearerTokenAusenteOuMalFormado() {
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.empty());

        service.logout("refresh-token", "token-sem-prefixo-bearer");

        verify(jwtBlacklistService, never()).revogar(any());
    }

    @Test
    void logout_deveEngolirExcecao_quandoBlacklistFalha() {
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.empty());
        doThrow(new RuntimeException("redis indisponivel")).when(jwtBlacklistService).revogar("access-token-123");

        service.logout("refresh-token", "Bearer access-token-123");

        verify(jwtBlacklistService).revogar("access-token-123");
    }

    // ---------- me ----------

    @Test
    void me_deveRetornarDadosDoUsuario_quandoTokenValido() {
        UUID id = UUID.randomUUID();
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(id.toString());
        when(claims.get("email", String.class)).thenReturn("a@a.com");
        when(claims.get("nome", String.class)).thenReturn("Nome Teste");
        when(claims.get("perfil", String.class)).thenReturn("PACIENTE");
        when(claims.get("referenciaId", String.class)).thenReturn(referenciaId.toString());
        when(claims.get("roles", List.class)).thenReturn(List.of("PACIENTE"));
        when(claims.get("permissions", List.class)).thenReturn(List.of("AGENDA_LER"));
        when(jwtService.extrairClaims("token-valido")).thenReturn(claims);

        var response = service.me("Bearer token-valido");

        assertThat(response.getId()).isEqualTo(id);
        assertThat(response.getEmail()).isEqualTo("a@a.com");
        assertThat(response.getNome()).isEqualTo("Nome Teste");
        assertThat(response.getPerfil()).isEqualTo("PACIENTE");
        assertThat(response.getReferenciaId()).isEqualTo(referenciaId);
        assertThat(response.getRoles()).containsExactly("PACIENTE");
        assertThat(response.getPermissions()).containsExactly("AGENDA_LER");
    }
}
