package br.com.sgsm.auth.dto;

public record OtpGerarResponse(String otp, long ttlSegundos) {}
