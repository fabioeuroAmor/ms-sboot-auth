package br.com.sgsm.auth.service;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtBlacklistServiceTest {

    @Mock
    private StringRedisTemplate redis;
    @Mock
    private JwtService jwtService;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private JwtBlacklistService service;

    @BeforeEach
    void setUp() {
        service = new JwtBlacklistService(redis, jwtService);
    }

    @Test
    void revogar_deveArmazenarNaBlacklistComTtlRestante_quandoTokenAindaValido() {
        Claims claims = mock(Claims.class);
        when(claims.getId()).thenReturn("jti-123");
        when(claims.getExpiration()).thenReturn(Date.from(Instant.now().plusSeconds(60)));
        when(jwtService.extrairClaims("token-valido")).thenReturn(claims);
        when(redis.opsForValue()).thenReturn(valueOperations);

        service.revogar("token-valido");

        verify(valueOperations).set(eq("blacklist:jti-123"), eq("revogado"), any(Duration.class));
    }

    @Test
    void revogar_naoDeveArmazenar_quandoTokenJaExpirado() {
        Claims claims = mock(Claims.class);
        when(claims.getExpiration()).thenReturn(Date.from(Instant.now().minusSeconds(60)));
        when(jwtService.extrairClaims("token-expirado")).thenReturn(claims);

        service.revogar("token-expirado");

        verify(redis, never()).opsForValue();
    }
}
