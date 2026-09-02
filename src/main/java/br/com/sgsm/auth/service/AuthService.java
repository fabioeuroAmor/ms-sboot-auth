package br.com.sgsm.auth.service;

import br.com.sgsm.auth.config.JwtProperties;
import br.com.sgsm.auth.domain.EntidadeAuth;
import br.com.sgsm.auth.domain.EventoAutenticacao;
import br.com.sgsm.auth.domain.RefreshToken;
import br.com.sgsm.auth.domain.Usuario;
import br.com.sgsm.auth.dto.*;
import br.com.sgsm.auth.exception.*;
import br.com.sgsm.auth.repository.*;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private static final Set<String> PERFIS_VALIDOS = Set.of("MEDICO", "PACIENTE", "FUNCIONARIO", "DESENVOLVEDOR");

    private final UsuarioRepository usuarioRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final EntidadeAuthRepository entidadeAuthRepository;
    private final JwtService jwtService;
    private final JwtBlacklistService jwtBlacklistService;
    private final PasswordEncoder passwordEncoder;
    private final JwtProperties jwtProperties;
    private final EmailService emailService;
    private final AutenticacaoAuditoriaService autenticacaoAuditoriaService;

    public AuthService(
            UsuarioRepository usuarioRepository,
            RoleRepository roleRepository,
            RefreshTokenRepository refreshTokenRepository,
            EntidadeAuthRepository entidadeAuthRepository,
            JwtService jwtService,
            JwtBlacklistService jwtBlacklistService,
            PasswordEncoder passwordEncoder,
            JwtProperties jwtProperties,
            EmailService emailService,
            AutenticacaoAuditoriaService autenticacaoAuditoriaService
    ) {
        this.usuarioRepository = usuarioRepository;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.entidadeAuthRepository = entidadeAuthRepository;
        this.jwtService = jwtService;
        this.jwtBlacklistService = jwtBlacklistService;
        this.passwordEncoder = passwordEncoder;
        this.jwtProperties = jwtProperties;
        this.emailService = emailService;
        this.autenticacaoAuditoriaService = autenticacaoAuditoriaService;
    }

    @Transactional(readOnly = true)
    public boolean emailDisponivel(String email) {
        return !usuarioRepository.existsByEmail(email);
    }

    public RegistrarResponse registrar(RegistrarRequest request) {
        if (!PERFIS_VALIDOS.contains(request.tipoPerfil())) {
            throw new IllegalArgumentException(
                    "tipoPerfil invalido. Valores aceitos: " + PERFIS_VALIDOS);
        }

        // DESENVOLVEDOR nao tem entidade no sgsm — sem validacao de referenciaId
        if ("DESENVOLVEDOR".equals(request.tipoPerfil())) {
            if (usuarioRepository.existsByEmail(request.email())) {
                throw new UsuarioJaExisteException("Email ja cadastrado: " + request.email());
            }

            var role = roleRepository.findByNome("DESENVOLVEDOR")
                    .orElseThrow(() -> new EntidadeNaoEncontradaException("Role nao encontrada: DESENVOLVEDOR"));

            var usuario = new Usuario();
            usuario.setEmail(request.email());
            usuario.setSenhaHash(passwordEncoder.encode(request.senha()));
            usuario.setTipoPerfil("DESENVOLVEDOR");
            usuario.setReferenciaId(null);
            usuario.setRoles(Set.of(role));

            var salvo = usuarioRepository.save(usuario);
            log.info("Usuario registrado: id={} email={} tipoPerfil=DESENVOLVEDOR", salvo.getId(), salvo.getEmail());
            registrarAuditoria(salvo.getId(), salvo.getEmail(), EventoAutenticacao.REGISTRO, "tipoPerfil=DESENVOLVEDOR");

            var response = new RegistrarResponse();
            response.setId(salvo.getId());
            response.setEmail(salvo.getEmail());
            response.setTipoPerfil(salvo.getTipoPerfil());
            response.setReferenciaId(null);
            response.setCriadoEm(salvo.getCriadoEm());
            return response;
        }

        // FUNCIONARIO nao conhece seu UUID: resolve referenciaId pelo email
        EntidadeAuth entidade;
        if ("FUNCIONARIO".equals(request.tipoPerfil()) && request.referenciaId() == null) {
            entidade = entidadeAuthRepository
                    .findByEmailAndTipo(request.email(), "FUNCIONARIO")
                    .orElseThrow(() -> new EntidadeNaoEncontradaException(
                            "Nenhum funcionario encontrado com email: " + request.email()));
        } else {
            entidade = entidadeAuthRepository
                    .findByReferenciaIdAndTipo(request.referenciaId(), request.tipoPerfil())
                    .orElseThrow(() -> new EntidadeNaoEncontradaException(
                            "Nenhum registro ativo encontrado para referenciaId=" + request.referenciaId()
                            + " com perfil=" + request.tipoPerfil()));
        }

        if (!entidade.getAtivo()) {
            throw new EntidadeNaoEncontradaException("A entidade referenciada esta inativa.");
        }
        // Comparacao explicita com Locale.ROOT (em vez de equalsIgnoreCase) para evitar
        // colisoes de case-folding dependentes de locale (ex.: "i" turco) apontadas pelo FindSecBugs.
        if (!entidade.getEmail().toLowerCase(Locale.ROOT).equals(request.email().toLowerCase(Locale.ROOT))) {
            throw new CredenciaisInvalidasException(
                    "O email informado nao corresponde ao registro referenciado.");
        }
        if (usuarioRepository.existsByEmail(request.email())) {
            log.warn("Tentativa de registro com email ja cadastrado: {}", request.email());
            throw new UsuarioJaExisteException("Email ja cadastrado: " + request.email());
        }

        var role = roleRepository.findByNome(request.tipoPerfil())
                .orElseThrow(() -> new EntidadeNaoEncontradaException(
                        "Role nao encontrada: " + request.tipoPerfil()));

        String senhaTextoClaro = request.senha();

        var usuario = new Usuario();
        usuario.setEmail(request.email());
        usuario.setSenhaHash(passwordEncoder.encode(senhaTextoClaro));
        usuario.setTipoPerfil(request.tipoPerfil());
        usuario.setReferenciaId(entidade.getReferenciaId());
        usuario.setRoles(Set.of(role));

        var salvo = usuarioRepository.save(usuario);

        emailService.enviarBoasVindas(salvo.getEmail(), entidade.getNome(),
                request.tipoPerfil(), senhaTextoClaro);
        log.info("Usuario registrado: id={} email={} tipoPerfil={}", salvo.getId(), salvo.getEmail(), salvo.getTipoPerfil());
        registrarAuditoria(salvo.getId(), salvo.getEmail(), EventoAutenticacao.REGISTRO, "tipoPerfil=" + salvo.getTipoPerfil());

        var response = new RegistrarResponse();
        response.setId(salvo.getId());
        response.setEmail(salvo.getEmail());
        response.setTipoPerfil(salvo.getTipoPerfil());
        response.setReferenciaId(salvo.getReferenciaId());
        response.setCriadoEm(salvo.getCriadoEm());
        return response;
    }

    public LoginResponse login(LoginRequest request) {
        var usuario = usuarioRepository.findByEmail(request.email())
                .orElseThrow(() -> {
                    log.warn("Login falhou: email nao cadastrado ({})", request.email());
                    registrarAuditoria(null, request.email(), EventoAutenticacao.LOGIN_FALHA, "email nao cadastrado");
                    return new CredenciaisInvalidasException("Credenciais invalidas.");
                });

        if (!usuario.getAtivo()) {
            log.warn("Login falhou: usuario inativo (id={} email={})", usuario.getId(), usuario.getEmail());
            registrarAuditoria(usuario.getId(), usuario.getEmail(), EventoAutenticacao.LOGIN_FALHA, "usuario inativo");
            throw new CredenciaisInvalidasException("Credenciais invalidas.");
        }
        if (!passwordEncoder.matches(request.senha(), usuario.getSenhaHash())) {
            log.warn("Login falhou: senha incorreta (id={} email={})", usuario.getId(), usuario.getEmail());
            registrarAuditoria(usuario.getId(), usuario.getEmail(), EventoAutenticacao.LOGIN_FALHA, "senha incorreta");
            throw new CredenciaisInvalidasException("Credenciais invalidas.");
        }

        // Valida que a entidade sgsm ainda esta ativa (DESENVOLVEDOR nao tem entidade)
        if (!"DESENVOLVEDOR".equals(usuario.getTipoPerfil())) {
            entidadeAuthRepository
                    .findByReferenciaIdAndTipo(usuario.getReferenciaId(), usuario.getTipoPerfil())
                    .filter(e -> Boolean.TRUE.equals(e.getAtivo()))
                    .orElseThrow(() -> {
                        log.warn("Login falhou: entidade vinculada inativa/removida (id={} email={} tipoPerfil={})",
                                usuario.getId(), usuario.getEmail(), usuario.getTipoPerfil());
                        registrarAuditoria(usuario.getId(), usuario.getEmail(),
                                EventoAutenticacao.LOGIN_FALHA, "entidade vinculada inativa ou removida");
                        return new CredenciaisInvalidasException("A entidade vinculada esta inativa ou foi removida.");
                    });
        }

        List<String> roles = usuario.getRoles().stream()
                .map(r -> r.getNome())
                .toList();

        List<String> permissions = usuario.getRoles().stream()
                .flatMap(r -> r.getPermissoes().stream())
                .map(p -> p.getNome())
                .distinct()
                .toList();

        String nome = "DESENVOLVEDOR".equals(usuario.getTipoPerfil())
                ? usuario.getEmail()
                : entidadeAuthRepository
                        .findByReferenciaIdAndTipo(usuario.getReferenciaId(), usuario.getTipoPerfil())
                        .map(e -> e.getNome())
                        .orElse(usuario.getEmail());

        String accessToken = jwtService.gerarToken(
                usuario.getId(), usuario.getEmail(), nome,
                usuario.getTipoPerfil(), usuario.getReferenciaId(),
                roles, permissions);

        String tokenRefresh = UUID.randomUUID().toString();
        var rt = new RefreshToken();
        rt.setUsuario(usuario);
        rt.setToken(tokenRefresh);
        rt.setExpiraEm(OffsetDateTime.now().plusDays(jwtProperties.refreshExpiracaoDias()));
        refreshTokenRepository.save(rt);
        log.info("Login bem-sucedido: id={} email={} tipoPerfil={}", usuario.getId(), usuario.getEmail(), usuario.getTipoPerfil());
        registrarAuditoria(usuario.getId(), usuario.getEmail(), EventoAutenticacao.LOGIN_SUCESSO, null);

        return new LoginResponse(accessToken, tokenRefresh, jwtService.expiracaoEmSegundos());
    }

    public RefreshResponse refresh(RefreshRequest request) {
        var rt = refreshTokenRepository.findByToken(request.refreshToken())
                .orElseThrow(() -> new TokenInvalidoException("Refresh token invalido."));

        if (Boolean.TRUE.equals(rt.getRevogado())) {
            // Reuso de refresh token ja revogado (rotacao) — indicio de token vazado/roubado.
            UUID usuarioIdRevogado = rt.getUsuario() != null ? rt.getUsuario().getId() : null;
            String emailRevogado = rt.getUsuario() != null ? rt.getUsuario().getEmail() : null;
            log.warn("Possivel reuso de refresh token revogado detectado: usuarioId={} email={}",
                    usuarioIdRevogado, emailRevogado);
            registrarAuditoria(usuarioIdRevogado, emailRevogado, EventoAutenticacao.REUSO_TOKEN_REVOGADO, null);
            throw new TokenInvalidoException("Refresh token revogado.");
        }
        if (rt.getExpiraEm().isBefore(OffsetDateTime.now())) {
            UUID usuarioIdExpirado = rt.getUsuario() != null ? rt.getUsuario().getId() : null;
            log.warn("Refresh falhou: token expirado (usuarioId={})", usuarioIdExpirado);
            registrarAuditoria(usuarioIdExpirado,
                    rt.getUsuario() != null ? rt.getUsuario().getEmail() : null,
                    EventoAutenticacao.REFRESH_FALHA, "token expirado");
            throw new TokenInvalidoException("Refresh token expirado.");
        }

        var usuario = rt.getUsuario();

        List<String> roles = usuario.getRoles().stream().map(r -> r.getNome()).toList();
        List<String> permissions = usuario.getRoles().stream()
                .flatMap(r -> r.getPermissoes().stream()).map(p -> p.getNome()).distinct().toList();

        String nome = "DESENVOLVEDOR".equals(usuario.getTipoPerfil())
                ? usuario.getEmail()
                : entidadeAuthRepository
                        .findByReferenciaIdAndTipo(usuario.getReferenciaId(), usuario.getTipoPerfil())
                        .map(e -> e.getNome()).orElse(usuario.getEmail());

        String novoAccessToken = jwtService.gerarToken(
                usuario.getId(), usuario.getEmail(), nome,
                usuario.getTipoPerfil(), usuario.getReferenciaId(), roles, permissions);

        // Rotacao do refresh token: o token usado e revogado e um novo e emitido,
        // para que o reuso de um refresh token vazado/roubado seja detectavel
        // (uma segunda tentativa com o token antigo encontrara "revogado=true").
        rt.setRevogado(true);
        refreshTokenRepository.save(rt);

        String novoRefreshToken = UUID.randomUUID().toString();
        var novoRt = new RefreshToken();
        novoRt.setUsuario(usuario);
        novoRt.setToken(novoRefreshToken);
        novoRt.setExpiraEm(OffsetDateTime.now().plusDays(jwtProperties.refreshExpiracaoDias()));
        refreshTokenRepository.save(novoRt);
        log.info("Refresh bem-sucedido: usuarioId={} email={}", usuario.getId(), usuario.getEmail());
        registrarAuditoria(usuario.getId(), usuario.getEmail(), EventoAutenticacao.REFRESH_SUCESSO, null);

        return new RefreshResponse(novoAccessToken, novoRefreshToken, jwtService.expiracaoEmSegundos());
    }

    // Método interno usado pelo OtpService para emitir tokens sem verificar senha.
    // O caller é responsável por autenticar o usuário via OTP antes de invocar este método.
    @Transactional
    public LoginResponse loginPorOtp(Usuario usuario) {
        if (!Boolean.TRUE.equals(usuario.getAtivo())) {
            throw new CredenciaisInvalidasException("Usuário inativo.");
        }

        List<String> roles = usuario.getRoles().stream()
                .map(r -> r.getNome())
                .toList();

        List<String> permissions = usuario.getRoles().stream()
                .flatMap(r -> r.getPermissoes().stream())
                .map(p -> p.getNome())
                .distinct()
                .toList();

        String nome = entidadeAuthRepository
                .findByReferenciaIdAndTipo(usuario.getReferenciaId(), usuario.getTipoPerfil())
                .map(e -> e.getNome())
                .orElse(usuario.getEmail());

        String accessToken = jwtService.gerarToken(
                usuario.getId(), usuario.getEmail(), nome,
                usuario.getTipoPerfil(), usuario.getReferenciaId(),
                roles, permissions);

        String tokenRefresh = UUID.randomUUID().toString();
        var rt = new RefreshToken();
        rt.setUsuario(usuario);
        rt.setToken(tokenRefresh);
        rt.setExpiraEm(OffsetDateTime.now().plusDays(jwtProperties.refreshExpiracaoDias()));
        refreshTokenRepository.save(rt);

        var response = new LoginResponse(accessToken, tokenRefresh, jwtService.expiracaoEmSegundos());
        response.setTipoPerfil(usuario.getTipoPerfil());
        return response;
    }

    public void logout(String refreshTokenStr, String bearerToken) {
        // Revoga o access token na blacklist do Redis (TTL automático)
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            try {
                jwtBlacklistService.revogar(bearerToken.substring(7));
            } catch (Exception ignored) {
                // token já expirado — não precisa entrar na blacklist
            }
        }
        // Revoga o refresh token no PostgreSQL
        refreshTokenRepository.findByToken(refreshTokenStr).ifPresent(rt -> {
            rt.setRevogado(true);
            refreshTokenRepository.save(rt);
            UUID usuarioId = rt.getUsuario() != null ? rt.getUsuario().getId() : null;
            String email = rt.getUsuario() != null ? rt.getUsuario().getEmail() : null;
            log.info("Logout: usuarioId={} email={}", usuarioId, email);
            registrarAuditoria(usuarioId, email, EventoAutenticacao.LOGOUT, null);
        });
    }

    @Transactional(readOnly = true)
    public MeResponse me(String bearerToken) {
        String token = bearerToken.replace("Bearer ", "");
        Claims claims = jwtService.extrairClaims(token);

        var response = new MeResponse();
        response.setId(UUID.fromString(claims.getSubject()));
        response.setEmail(claims.get("email", String.class));
        response.setNome(claims.get("nome", String.class));
        response.setPerfil(claims.get("perfil", String.class));
        String referenciaIdStr = claims.get("referenciaId", String.class);
        response.setReferenciaId(referenciaIdStr != null ? UUID.fromString(referenciaIdStr) : null);
        response.setRoles(claims.get("roles", List.class));
        response.setPermissions(claims.get("permissions", List.class));
        return response;
    }

    // Auditoria roda em transação própria (ver AutenticacaoAuditoriaService); uma falha ali
    // (ex.: banco indisponível) não pode impedir login/registro/refresh que já foi concluído,
    // só fica registrada em log.
    private void registrarAuditoria(UUID usuarioId, String email, EventoAutenticacao evento, String detalhe) {
        try {
            autenticacaoAuditoriaService.registrar(usuarioId, email, evento, detalhe);
        } catch (Exception e) {
            log.warn("Falha ao registrar auditoria de autenticacao {} para {}: {}", evento, email, e.getMessage());
        }
    }
}
