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

import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    private static final String OTP_KEY = "auth:otp:a@a.com";
    private static final String TENTATIVAS_KEY = "auth:otp:tentativas:a@a.com";

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
        usuario.setEmail(email);
        return usuario;
    }

    // ---------- gerar ----------

    @Test
    void gerar_deveLancarIllegalArgument_quandoEmailNaoEncontrado() {
        when(usuarioRepository.findByEmail("inexistente@a.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.gerar("inexistente@a.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("E-mail não encontrado.");
    }

    @Test
    void gerar_deveArmazenarOtpNoRedisEResetarTentativas_quandoEmailExiste() {
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario("a@a.com")));
        when(redis.opsForValue()).thenReturn(valueOperations);

        var response = service.gerar("a@a.com");

        assertThat(response.otp()).hasSize(6);
        assertThat(response.ttlSegundos()).isEqualTo(300L);
        verify(valueOperations).set(eq(OTP_KEY), eq(response.otp()), eq(300L), eq(TimeUnit.SECONDS));
        verify(redis).delete(TENTATIVAS_KEY);
    }

    // ---------- verificar ----------

    @Test
    void verificar_deveLancarIllegalArgument_quandoMaximoDeTentativasAtingido() {
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_KEY)).thenReturn("3");

        assertThatThrownBy(() -> service.verificar("a@a.com", "123456"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Máximo de tentativas atingido");

        verify(valueOperations, never()).get(OTP_KEY);
    }

    @Test
    void verificar_deveLancarIllegalArgument_quandoOtpExpiradoOuInexistente() {
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_KEY)).thenReturn(null);
        when(valueOperations.get(OTP_KEY)).thenReturn(null);

        assertThatThrownBy(() -> service.verificar("a@a.com", "123456"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Código expirado ou inválido");
    }

    @Test
    void verificar_deveIncrementarTentativasELancarCredenciaisInvalidas_quandoOtpIncorreto() {
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_KEY)).thenReturn("1");
        when(valueOperations.get(OTP_KEY)).thenReturn("999999");

        assertThatThrownBy(() -> service.verificar("a@a.com", "123456"))
                .isInstanceOf(CredenciaisInvalidasException.class)
                .hasMessageContaining("Código incorreto.");

        verify(valueOperations).increment(TENTATIVAS_KEY);
        verify(redis).expire(eq(TENTATIVAS_KEY), eq(300L), eq(TimeUnit.SECONDS));
    }

    @Test
    void verificar_deveLancarIllegalArgument_quandoUsuarioNaoEncontradoAposOtpValido() {
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_KEY)).thenReturn(null);
        when(valueOperations.get(OTP_KEY)).thenReturn("123456");
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verificar("a@a.com", "123456"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Usuário não encontrado.");

        verify(redis).delete(OTP_KEY);
        verify(redis).delete(TENTATIVAS_KEY);
    }

    @Test
    void verificar_deveRetornarLoginResponse_quandoOtpValido() {
        Usuario usuario = usuario("a@a.com");
        var loginResponse = new LoginResponse("access", "refresh", 900L);
        when(redis.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(TENTATIVAS_KEY)).thenReturn(null);
        when(valueOperations.get(OTP_KEY)).thenReturn("123456");
        when(usuarioRepository.findByEmail("a@a.com")).thenReturn(Optional.of(usuario));
        when(authService.loginPorOtp(usuario)).thenReturn(loginResponse);

        var response = service.verificar("a@a.com", "123456");

        assertThat(response).isSameAs(loginResponse);
        verify(redis).delete(OTP_KEY);
        verify(redis).delete(TENTATIVAS_KEY);
    }
}
