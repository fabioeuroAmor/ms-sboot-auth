package br.com.sgsm.auth.service;

import br.com.sgsm.auth.dto.LoginResponse;
import br.com.sgsm.auth.dto.OtpGerarResponse;
import br.com.sgsm.auth.exception.CredenciaisInvalidasException;
import br.com.sgsm.auth.repository.UsuarioRepository;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class OtpService {

    private static final String OTP_PREFIX = "auth:otp:";
    private static final long TTL_SEGUNDOS = 300L; // 5 minutos
    private static final String TENTATIVAS_PREFIX = "auth:otp:tentativas:";
    private static final int MAX_TENTATIVAS = 3;

    private final StringRedisTemplate redis;
    private final UsuarioRepository usuarioRepository;
    private final AuthService authService;

    public OtpService(StringRedisTemplate redis,
                      UsuarioRepository usuarioRepository,
                      AuthService authService) {
        this.redis = redis;
        this.usuarioRepository = usuarioRepository;
        this.authService = authService;
    }

    public OtpGerarResponse gerar(String email) {
        // Verifica se o usuário existe
        usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("E-mail não encontrado."));

        // Gera OTP de 6 dígitos com padding de zeros
        String otp = String.format("%06d", (int) (Math.random() * 1_000_000));

        // Armazena no Redis com TTL
        redis.opsForValue().set(OTP_PREFIX + email, otp, TTL_SEGUNDOS, TimeUnit.SECONDS);
        // Reseta contador de tentativas
        redis.delete(TENTATIVAS_PREFIX + email);

        return new OtpGerarResponse(otp, TTL_SEGUNDOS);
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
