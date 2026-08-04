package org.yuktisetu.authservice.dto;

public record RoleAssignmentDTO(
        String role,
        Long collegeId,
        Long deptId
) {}
