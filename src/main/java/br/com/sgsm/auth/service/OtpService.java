package br.com.sgsm.auth.service;

import br.com.sgsm.auth.dto.LoginResponse;
import br.com.sgsm.auth.dto.OtpGerarResponse;
import br.com.sgsm.auth.exception.CredenciaisInvalidasException;
import br.com.sgsm.auth.exception.TokenInvalidoException;
import br.com.sgsm.auth.repository.UsuarioRepository;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

@Service
public class OtpService {

    private static final String OTP_PREFIX = "auth:otp:";
    private static final long TTL_SEGUNDOS = 300L; // 5 minutos
    private static final String TENTATIVAS_PREFIX = "auth:otp:tentativas:";
    private static final int MAX_TENTATIVAS = 3;
    private static final String PERFIL_SISTEMA = "DESENVOLVEDOR";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final StringRedisTemplate redis;
    private final UsuarioRepository usuarioRepository;
    private final AuthService authService;
    private final JwtService jwtService;

    public OtpService(StringRedisTemplate redis,
                      UsuarioRepository usuarioRepository,
                      AuthService authService,
                      JwtService jwtService) {
        this.redis = redis;
        this.usuarioRepository = usuarioRepository;
        this.authService = authService;
        this.jwtService = jwtService;
    }

    // Só o bot sistema (ms-whatsapp-bot, autenticado com o JWT de perfil DESENVOLVEDOR
    // configurado em bot.sistema.jwt) pode disparar a geração de OTP de outro usuário —
    // sem essa checagem, qualquer requisição anônima conseguia ler o código de qualquer
    // e-mail direto na resposta HTTP.
    public OtpGerarResponse gerar(String email, String authorizationHeader) {
        exigirPerfilSistema(authorizationHeader);

        // Verifica se o usuário existe
        usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("E-mail não encontrado."));

        // Gera OTP de 6 dígitos com padding de zeros, usando um CSPRNG (SecureRandom)
        String otp = String.format("%06d", SECURE_RANDOM.nextInt(1_000_000));

        // Armazena no Redis com TTL
        redis.opsForValue().set(OTP_PREFIX + email, otp, TTL_SEGUNDOS, TimeUnit.SECONDS);
        // Reseta contador de tentativas
        redis.delete(TENTATIVAS_PREFIX + email);

        return new OtpGerarResponse(otp, TTL_SEGUNDOS);
    }

    private void exigirPerfilSistema(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new TokenInvalidoException("Token do bot sistema ausente.");
        }
        var claims = jwtService.extrairClaims(authorizationHeader.substring(7));
        if (!PERFIL_SISTEMA.equals(claims.get("perfil", String.class))) {
            throw new CredenciaisInvalidasException("Apenas o bot sistema pode gerar OTP para outro usuário.");
        }
    }

    public LoginResponse verificar(String email, String otp) {
        // Rate limiting: máx 3 tentativas incorretas
        String tentativasKey = TENTATIVAS_PREFIX + email;
        String tentativasStr = redis.opsForValue().get(tentativasKey);
        int tentativas = tentativasStr == null ? 0 : Integer.parseInt(tentativasStr);
        if (tentativas >= MAX_TENTATIVAS) {
            throw new IllegalArgumentException("Máximo de tentativas atingido. Solicite um novo código.");
        }

        String otpArmazenado = redis.opsForValue().get(OTP_PREFIX + email);
        if (otpArmazenado == null) {
            throw new IllegalArgumentException("Código expirado ou inválido. Solicite um novo.");
        }

        if (!otpArmazenado.equals(otp)) {
            // Incrementa contador de tentativas
            redis.opsForValue().increment(tentativasKey);
            redis.expire(tentativasKey, TTL_SEGUNDOS, TimeUnit.SECONDS);
            throw new CredenciaisInvalidasException("Código incorreto.");
        }

        // OTP válido — apaga do Redis
        redis.delete(OTP_PREFIX + email);
        redis.delete(tentativasKey);

        // Busca usuário e emite JWT usando AuthService (sem duplicar lógica de geração de token)
        var usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado."));

        return authService.loginPorOtp(usuario);
    }
}
