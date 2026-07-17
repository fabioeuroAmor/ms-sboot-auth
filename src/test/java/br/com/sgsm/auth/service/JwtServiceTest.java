package br.com.sgsm.auth.service;

import br.com.sgsm.auth.config.JwtProperties;
import br.com.sgsm.auth.exception.TokenInvalidoException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET = "sgsm-chave-de-teste-minimo-256-bits-para-hmac-sha-nao-usar-em-producao";

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        JwtProperties props = new JwtProperties(SECRET, 15, 7);
        jwtService = new JwtService(props);
    }

    @Test
    void gerarToken_deveGerarTokenComTodasAsClaims() {
        UUID usuarioId = UUID.randomUUID();
        UUID referenciaId = UUID.randomUUID();

        String token = jwtService.gerarToken(usuarioId, "a@a.com", "Nome Teste", "PACIENTE",
                referenciaId, List.of("PACIENTE"), List.of("AGENDA_LER"));

        Claims claims = jwtService.extrairClaims(token);
        assertThat(claims.getSubject()).isEqualTo(usuarioId.toString());
        assertThat(claims.get("email", String.class)).isEqualTo("a@a.com");
        assertThat(claims.get("nome", String.class)).isEqualTo("Nome Teste");
        assertThat(claims.get("perfil", String.class)).isEqualTo("PACIENTE");
        assertThat(claims.get("referenciaId", String.class)).isEqualTo(referenciaId.toString());
        assertThat(claims.get("roles", List.class)).containsExactly("PACIENTE");
        assertThat(claims.get("permissions", List.class)).containsExactly("AGENDA_LER");
        assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
    }

    @Test
    void extrairEmail_deveRetornarEmailDoToken() {
        String token = jwtService.gerarToken(UUID.randomUUID(), "email@teste.com", "Nome",
                "MEDICO", UUID.randomUUID(), List.of("MEDICO"), List.of());

        assertThat(jwtService.extrairEmail(token)).isEqualTo("email@teste.com");
    }

    @Test
    void extrairClaims_deveLancarTokenInvalido_quandoTokenMalformado() {
        assertThatThrownBy(() -> jwtService.extrairClaims("token-completamente-invalido"))
                .isInstanceOf(TokenInvalidoException.class)
                .hasMessageContaining("invalido ou expirado");
    }

    @Test
    void extrairClaims_deveLancarTokenInvalido_quandoAssinaturaNaoConfere() {
        SecretKey outraChave = Keys.hmacShaKeyFor(
                "outra-chave-completamente-diferente-com-256-bits-de-tamanho".getBytes(StandardCharsets.UTF_8));
        Instant agora = Instant.now();
        String tokenComOutraAssinatura = Jwts.builder()
                .subject(UUID.randomUUID().toString())
                .issuedAt(Date.from(agora))
                .expiration(Date.from(agora.plusSeconds(60)))
                .signWith(outraChave)
                .compact();

        assertThatThrownBy(() -> jwtService.extrairClaims(tokenComOutraAssinatura))
                .isInstanceOf(TokenInvalidoException.class);
    }

    @Test
    void extrairClaims_deveLancarTokenInvalido_quandoTokenExpirado() {
        SecretKey chave = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        Instant passado = Instant.now().minusSeconds(3600);
        String tokenExpirado = Jwts.builder()
                .subject(UUID.randomUUID().toString())
                .issuedAt(Date.from(passado))
                .expiration(Date.from(passado.plusSeconds(1)))
                .signWith(chave)
                .compact();

        assertThatThrownBy(() -> jwtService.extrairClaims(tokenExpirado))
                .isInstanceOf(TokenInvalidoException.class);
    }

    @Test
    void expiracaoEmSegundos_deveConverterMinutosConfiguradosParaSegundos() {
        JwtProperties props = new JwtProperties(SECRET, 15, 7);
        JwtService service = new JwtService(props);

        assertThat(service.expiracaoEmSegundos()).isEqualTo(15L * 60);
    }
}
