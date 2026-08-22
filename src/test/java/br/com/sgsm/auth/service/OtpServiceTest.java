package br.com.sgsm.auth.service;

import br.com.sgsm.auth.domain.Usuario;
import br.com.sgsm.auth.dto.LoginResponse;
import br.com.sgsm.auth.exception.CredenciaisInvalidasException;
import br.com.sgsm.auth.repository.UsuarioRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    private static final String OTP_PREFIX = "auth:otp:";
    private static final String TENTATIVAS_PREFIX = "auth:otp:tentativas:";
    private static final long TTL_SEGUNDOS = 300L;

    @Mock
    private StringRedisTemplate redis;
    @Mock
    private UsuarioRepository usuarioRepository;
    @Mock
    private AuthService authService;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private OtpService service;

    @BeforeEach
    void setUp() {
        service = new OtpService(redis, usuarioRepository, authService);
    }

    private Usuario usuario(String email) {
        Usuario usuario = new Usuario();
        ReflectionTestUtils.setField(usuario, "id", UUID.randomUUID());
        usuario.setEmail(email);
        usuario.setAtivo(true);
        return usuario;
    }

    // ---------- gerar ----------

    @Test
    void gerar_deveLancarIllegalArgument_quandoEmailNaoEncontrado() {
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.gerar("a@a.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("E-mail não encontrado");
    }

    @Test
    void gerar_deveArmazenarOtpEZerarTentativas_quandoEmailValido() {
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario("a@a.com")));
        when(redis.opsForValue()).thenReturn(valueOperations);

        var response = service.gerar("a@a.com");

        assertThat(response.otp()).matches("\\d{6}");
        assertThat(response.ttlSegundos()).isEqualTo(TTL_SEGUNDOS);

        verify(valueOperations).set(eq(OTP_PREFIX + "a@a.com"), eq(response.otp()), eq(TTL_SEGUNDOS), eq(TimeUnit.SECONDS));
        verify(redis).delete(TENTATIVAS_PREFIX + "a@a.com");
    }

    // ---------- verificar ----------

    @Test
    void verificar_deveLancarIllegalArgument_quandoMaximoTentativasAtingido() {
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_PREFIX + "a@a.com")).thenReturn("3");

        assertThatThrownBy(() -> service.verificar("a@a.com", "123456"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Máximo de tentativas");
    }

    @Test
    void verificar_deveLancarIllegalArgument_quandoOtpExpiradoOuInexistente() {
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_PREFIX + "a@a.com")).thenReturn(null);
        when(valueOperations.get(OTP_PREFIX + "a@a.com")).thenReturn(null);

        assertThatThrownBy(() -> service.verificar("a@a.com", "123456"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expirado ou inválido");
    }

    @Test
    void verificar_deveIncrementarTentativasELancarCredenciaisInvalidas_quandoOtpIncorreto() {
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_PREFIX + "a@a.com")).thenReturn(null);
        when(valueOperations.get(OTP_PREFIX + "a@a.com")).thenReturn("123456");

        assertThatThrownBy(() -> service.verificar("a@a.com", "000000"))
                .isInstanceOf(CredenciaisInvalidasException.class)
                .hasMessageContaining("Código incorreto");

        verify(valueOperations).increment(TENTATIVAS_PREFIX + "a@a.com");
        verify(redis).expire(TENTATIVAS_PREFIX + "a@a.com", TTL_SEGUNDOS, TimeUnit.SECONDS);
    }

    @Test
    void verificar_deveLancarIllegalArgument_quandoUsuarioNaoEncontradoAposOtpValido() {
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_PREFIX + "a@a.com")).thenReturn(null);
        when(valueOperations.get(OTP_PREFIX + "a@a.com")).thenReturn("123456");
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verificar("a@a.com", "123456"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Usuário não encontrado");

        verify(redis).delete(OTP_PREFIX + "a@a.com");
        verify(redis).delete(TENTATIVAS_PREFIX + "a@a.com");
    }

    @Test
    void verificar_deveLimparRedisEEmitirToken_quandoOtpCorreto() {
        Usuario usuario = usuario("a@a.com");
        LoginResponse loginResponse = new LoginResponse("access", "refresh", 900L);

        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_PREFIX + "a@a.com")).thenReturn(null);
        when(valueOperations.get(OTP_PREFIX + "a@a.com")).thenReturn("123456");
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));
        when(authService.loginPorOtp(usuario)).thenReturn(loginResponse);

        var response = service.verificar("a@a.com", "123456");

        assertThat(response).isSameAs(loginResponse);
        verify(redis).delete(OTP_PREFIX + "a@a.com");
        verify(redis).delete(TENTATIVAS_PREFIX + "a@a.com");
        verify(valueOperations, never()).increment(anyString());
    }
}
