package br.com.sgsm.auth.service;

import br.com.sgsm.auth.config.JwtProperties;
import br.com.sgsm.auth.exception.TokenInvalidoException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public final class JwtService {

    private final SecretKey chave;
    private final long expiracaoMs;

    public JwtService(JwtProperties props) {
        this.chave = Keys.hmacShaKeyFor(props.secret().getBytes(StandardCharsets.UTF_8));
        this.expiracaoMs = (long) props.expiracaoMinutos() * 60 * 1000;
    }

    public String gerarToken(
            UUID usuarioId,
            String email,
            String nome,
            String perfil,
            UUID referenciaId,
            List<String> roles,
            List<String> permissions
    ) {
        Instant agora = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(usuarioId.toString())
                .claim("email", email)
                .claim("nome", nome)
                .claim("perfil", perfil)
                .claim("referenciaId", referenciaId.toString())
                .claim("roles", roles)
                .claim("permissions", permissions)
                .issuedAt(Date.from(agora))
                .expiration(Date.from(agora.plusMillis(expiracaoMs)))
                .signWith(chave)
                .compact();
    }

    public Claims extrairClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(chave)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            throw new TokenInvalidoException("Token invalido ou expirado.");
        }
    }

    public String extrairEmail(String token) {
        return extrairClaims(token).get("email", String.class);
    }

    public long expiracaoEmSegundos() {
        return expiracaoMs / 1000;
    }
}
