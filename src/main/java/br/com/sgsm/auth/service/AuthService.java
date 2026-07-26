package br.com.sgsm.auth.service;

import br.com.sgsm.auth.config.JwtProperties;
import br.com.sgsm.auth.domain.EntidadeAuth;
import br.com.sgsm.auth.domain.RefreshToken;
import br.com.sgsm.auth.domain.Usuario;
import br.com.sgsm.auth.dto.*;
import br.com.sgsm.auth.exception.*;
import br.com.sgsm.auth.repository.*;
import io.jsonwebtoken.Claims;
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

    public AuthService(
            UsuarioRepository usuarioRepository,
            RoleRepository roleRepository,
            RefreshTokenRepository refreshTokenRepository,
            EntidadeAuthRepository entidadeAuthRepository,
            JwtService jwtService,
            JwtBlacklistService jwtBlacklistService,
            PasswordEncoder passwordEncoder,
            JwtProperties jwtProperties,
            EmailService emailService
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
    }

    public RegistrarResponse registrar(RegistrarRequest request) {
        if (!PERFIS_VALIDOS.contains(request.tipoPerfil())) {
            throw new IllegalArgumentException(
                    "tipoPerfil invalido. Valores aceitos: " + PERFIS_VALIDOS);
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
                .orElseThrow(() -> new CredenciaisInvalidasException("Credenciais invalidas."));

        if (!usuario.getAtivo()) {
            throw new CredenciaisInvalidasException("Credenciais invalidas.");
        }
        if (!passwordEncoder.matches(request.senha(), usuario.getSenhaHash())) {
            throw new CredenciaisInvalidasException("Credenciais invalidas.");
        }

        // Valida que a entidade sgsm ainda esta ativa
        entidadeAuthRepository
                .findByReferenciaIdAndTipo(usuario.getReferenciaId(), usuario.getTipoPerfil())
                .filter(e -> Boolean.TRUE.equals(e.getAtivo()))
                .orElseThrow(() -> new CredenciaisInvalidasException(
                        "A entidade vinculada esta inativa ou foi removida."));

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

        return new LoginResponse(accessToken, tokenRefresh, jwtService.expiracaoEmSegundos());
    }

    public RefreshResponse refresh(RefreshRequest request) {
        var rt = refreshTokenRepository.findByToken(request.refreshToken())
                .orElseThrow(() -> new TokenInvalidoException("Refresh token invalido."));

        if (Boolean.TRUE.equals(rt.getRevogado())) {
            throw new TokenInvalidoException("Refresh token revogado.");
        }
        if (rt.getExpiraEm().isBefore(OffsetDateTime.now())) {
            throw new TokenInvalidoException("Refresh token expirado.");
        }

        var usuario = rt.getUsuario();

        List<String> roles = usuario.getRoles().stream().map(r -> r.getNome()).toList();
        List<String> permissions = usuario.getRoles().stream()
                .flatMap(r -> r.getPermissoes().stream()).map(p -> p.getNome()).distinct().toList();

        String nome = entidadeAuthRepository
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

        return new RefreshResponse(novoAccessToken, novoRefreshToken, jwtService.expiracaoEmSegundos());
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
        response.setReferenciaId(UUID.fromString(claims.get("referenciaId", String.class)));
        response.setRoles(claims.get("roles", List.class));
        response.setPermissions(claims.get("permissions", List.class));
        return response;
    }
}
