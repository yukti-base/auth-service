package org.yuktisetu.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.yuktisetu.identity.model.RoleType;

public record RegisterRequest(
        @NotBlank @Email String email,
        @NotBlank String phone,
        @NotBlank String password,
        @NotNull RoleType role,
        String firstName,
        String lastName
) {}
