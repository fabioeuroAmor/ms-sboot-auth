package br.com.sgsm.auth.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

// Contador simples de tentativas por chave (email, IP, etc.) com janela deslizante via TTL do
// Redis. Usado para limitar brute force de login e enumeração de e-mail — mesma técnica já usada
// para as tentativas de OTP em OtpService, só que reutilizável para outros endpoints.
@Service
public class RateLimiterService {

    private final StringRedisTemplate redis;

    public RateLimiterService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public boolean limiteExcedido(String chave, int maxTentativas) {
        String valor = redis.opsForValue().get(chave);
        int tentativas = valor == null ? 0 : Integer.parseInt(valor);
        return tentativas >= maxTentativas;
    }

    public void incrementar(String chave, long janelaSegundos) {
        redis.opsForValue().increment(chave);
        redis.expire(chave, janelaSegundos, TimeUnit.SECONDS);
    }

    public void resetar(String chave) {
        redis.delete(chave);
    }
}
