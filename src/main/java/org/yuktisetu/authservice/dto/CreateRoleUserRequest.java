package org.yuktisetu.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.yuktisetu.model.RoleType;

public record CreateRoleUserRequest(
        @NotBlank @Email String email,
        @NotBlank String phone,
        @NotBlank String firstName,
        String lastName,     // optional — not everyone has one
        @NotNull RoleType role,
        Long collegeId,
        Long deptId
) {
}
