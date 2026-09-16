package org.yuktisetu.authservice.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yuktisetu.authservice.dto.ChangePasswordRequest;
import org.yuktisetu.authservice.dto.LoginRequest;
import org.yuktisetu.authservice.dto.LoginResponse;
import org.yuktisetu.authservice.dto.RefreshTokenRequest;
import org.yuktisetu.authservice.dto.RegisterRequest;
import org.yuktisetu.authservice.dto.RegisterResponse;
import org.yuktisetu.authservice.service.AuthService;
import org.yuktisetu.core.response.YuktiSetuResponse;
import org.yuktisetu.core.security.UserPrincipal;

@Slf4j
@RestController
@RequestMapping
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<YuktiSetuResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(YuktiSetuResponse.success(authService.login(request), "Login successful"));
    }

    @PostMapping("/register")
    public ResponseEntity<YuktiSetuResponse<RegisterResponse>> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(YuktiSetuResponse.success(authService.register(request), "Registration successful"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<YuktiSetuResponse<LoginResponse>> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(YuktiSetuResponse.success(authService.refresh(request.refreshToken()), "Token refreshed"));
    }

    @PostMapping("/logout")
    public ResponseEntity<YuktiSetuResponse<Void>> logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request.refreshToken());
        return ResponseEntity.ok(YuktiSetuResponse.success(null, "Logged out"));
    }

    @PostMapping("/change-password")
    public ResponseEntity<YuktiSetuResponse<Void>> changePassword(
            @AuthenticationPrincipal UserPrincipal actor,
            @Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(actor.userId(), request);
        return ResponseEntity.ok(YuktiSetuResponse.success(null, "Password changed"));
    }
}
