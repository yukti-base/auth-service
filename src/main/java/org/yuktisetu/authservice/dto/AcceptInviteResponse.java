package org.yuktisetu.authservice.dto;

public record AcceptInviteResponse(
        String role,
        boolean isAdmin
) {}