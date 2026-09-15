package br.com.sgsm.auth.controller;

import br.com.sgsm.auth.dto.LoginResponse;
import br.com.sgsm.auth.dto.OtpGerarRequest;
import br.com.sgsm.auth.dto.OtpGerarResponse;
import br.com.sgsm.auth.dto.OtpVerificarRequest;
import br.com.sgsm.auth.service.OtpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/api/auth/otp")
@Tag(name = "OTP", description = "Autenticação via código temporário para canal WhatsApp")
public class OtpController {

    private final OtpService otpService;

    public OtpController(OtpService otpService) {
        this.otpService = otpService;
    }

    @PostMapping("/gerar")
    @Operation(summary = "Gera OTP para autenticação WhatsApp (retorna código ao bot sistema, que o repassa por WhatsApp)")
    public ResponseEntity<OtpGerarResponse> gerar(
            @RequestBody OtpGerarRequest request,
            @RequestHeader("Authorization") String authorization) {
        return ResponseEntity.ok(otpService.gerar(request.email(), authorization));
    }

    @PostMapping("/verificar")
    @Operation(summary = "Verifica OTP e emite JWT com tipoPerfil")
    public ResponseEntity<LoginResponse> verificar(@RequestBody OtpVerificarRequest request) {
        return ResponseEntity.ok(otpService.verificar(request.email(), request.otp()));
    }
}
