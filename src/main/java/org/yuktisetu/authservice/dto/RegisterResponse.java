package org.yuktisetu.authservice.dto;

import org.yuktisetu.identity.model.UserStatus;

public record RegisterResponse(
        Long userId,
        String email,
        String phone,
        UserStatus status,
        String role,
        String token
) {}
