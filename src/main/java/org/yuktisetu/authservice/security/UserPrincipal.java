package org.yuktisetu.authservice.security;

import java.util.List;
import java.util.UUID;

/**
 * This shape is what every OTHER microservice should reconstruct locally from
 * the JWT (verify with the public key, read these claims) — nobody calls back
 * to auth-service per request. Keep this DTO's field names identical to the
 * claim names in JwtTokenProvider so services can copy this class verbatim.
 */
public record UserPrincipal(
        Long userId,
        String email,
        List<RoleClaim> roles
) {
    public record RoleClaim(String role, Long collegeId, Long deptId) {}
}
