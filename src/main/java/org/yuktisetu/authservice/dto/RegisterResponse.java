package org.yuktisetu.authservice.dto;

import org.yuktisetu.model.UserStatus;

public record RegisterResponse(
        Long userId,
        String email,
        String phone,
        UserStatus status,
        String role,
        String token
) {}
