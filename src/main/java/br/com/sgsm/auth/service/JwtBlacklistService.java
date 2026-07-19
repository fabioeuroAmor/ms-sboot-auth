package br.com.sgsm.auth.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtBlacklistService {

    private static final String PREFIX = "blacklist:";

    private final StringRedisTemplate redis;
    private final JwtService jwtService;

    public JwtBlacklistService(StringRedisTemplate redis, JwtService jwtService) {
        this.redis = redis;
        this.jwtService = jwtService;
    }

    // Insere JTI na blacklist com TTL igual ao tempo restante do token
    public void revogar(String accessToken) {
        var claims = jwtService.extrairClaims(accessToken);
        String jti = claims.getId();
        Date exp = claims.getExpiration();
        long ttlSegundos = Duration.between(Instant.now(), exp.toInstant()).getSeconds();
        if (ttlSegundos > 0) {
            redis.opsForValue().set(PREFIX + jti, "revogado", Duration.ofSeconds(ttlSegundos));
        }
    }
}
