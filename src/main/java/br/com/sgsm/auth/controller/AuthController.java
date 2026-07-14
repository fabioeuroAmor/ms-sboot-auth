package br.com.sgsm.auth.controller;

import br.com.sgsm.auth.dto.*;
import br.com.sgsm.auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/api/auth")
public class AuthController {

    private final AuthService service;

    public AuthController(AuthService service) {
        this.service = service;
    }

    // UC - Registrar usuario vinculado a entidade sgsm
    @PostMapping("/registrar")
    public ResponseEntity<RegistrarResponse> registrar(@RequestBody RegistrarRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.registrar(request));
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

    // UC - Revogar refresh token (logout)
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequest request) {
        service.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
