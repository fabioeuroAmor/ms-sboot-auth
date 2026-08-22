package br.com.sgsm.auth.controller;

import br.com.sgsm.auth.dto.*;
import br.com.sgsm.auth.service.AuthService;
import br.com.sgsm.auth.service.ResetSenhaService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/api/auth")
public class AuthController {

    private final AuthService service;
    private final ResetSenhaService resetSenhaService;

    public AuthController(AuthService service, ResetSenhaService resetSenhaService) {
        this.service = service;
        this.resetSenhaService = resetSenhaService;
    }

    // UC - Registrar usuario vinculado a entidade sgsm
    @PostMapping("/registrar")
    public ResponseEntity<RegistrarResponse> registrar(@RequestBody RegistrarRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.registrar(request));
    }

    // UC - Checar disponibilidade de e-mail antes de iniciar um auto-cadastro
    // (evita criar um medico/paciente orfao no sgsm quando o e-mail ja esta em uso)
    @GetMapping("/email-disponivel")
    public ResponseEntity<EmailDisponivelResponse> emailDisponivel(@RequestParam String email) {
        return ResponseEntity.ok(new EmailDisponivelResponse(service.emailDisponivel(email)));
    }

    // UC - Autenticar e obter tokens
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(service.login(request));
    }

    // UC - Dados do usuario logado
    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(@RequestHeader("Authorization") String authorization) {
        return ResponseEntity.ok(service.me(authorization));
    }

    // UC - Renovar access token
    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@RequestBody RefreshRequest request) {
        return ResponseEntity.ok(service.refresh(request));
    }

    // UC - Revogar refresh token e invalidar access token na blacklist Redis
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestBody LogoutRequest request,
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        service.logout(request.refreshToken(), authorization);
        return ResponseEntity.noContent().build();
    }

    // UC - Solicitar link de reset de senha por e-mail
    @PostMapping("/esqueci-senha")
    public ResponseEntity<Void> esqueciSenha(@RequestBody EsqueciSenhaRequest request) {
        resetSenhaService.solicitarReset(request.email());
        return ResponseEntity.ok().build();
    }

    // UC - Redefinir senha via token recebido por e-mail
    @PostMapping("/resetar-senha")
    public ResponseEntity<Void> resetarSenha(@RequestBody ResetarSenhaRequest request) {
        resetSenhaService.resetarSenha(request.token(), request.novaSenha());
        return ResponseEntity.noContent().build();
    }

    // UC - Alterar senha estando logado
    @PostMapping("/alterar-senha")
    public ResponseEntity<Void> alterarSenha(
            @RequestBody AlterarSenhaRequest request,
            @RequestHeader("Authorization") String authorization) {
        resetSenhaService.alterarSenha(authorization, request.senhaAtual(), request.novaSenha());
        return ResponseEntity.noContent().build();
    }
}
