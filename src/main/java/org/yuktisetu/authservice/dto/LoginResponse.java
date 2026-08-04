package org.yuktisetu.authservice.dto;

import java.util.List;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        long accessTokenExpiresInSeconds,
        Long userId,
        String email,
        List<RoleAssignmentDTO> roles
) {}
