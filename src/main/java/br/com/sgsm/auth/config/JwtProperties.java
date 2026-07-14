package br.com.sgsm.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String secret,
        int expiracaoMinutos,
        int refreshExpiracaoDias
) {}
