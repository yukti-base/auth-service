package org.yuktisetu.authservice.dto;

import org.yuktisetu.identity.model.RoleType;

public record DeactivateRoleRequest(Long targetUserId,
                                    RoleType targetRole,
                                    Long collegeId,
                                    Long deptId
) {
}
