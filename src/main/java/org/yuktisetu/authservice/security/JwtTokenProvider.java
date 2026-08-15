package org.yuktisetu.authservice.security;

import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;
import org.yuktisetu.authservice.config.JwtProperties;
import org.yuktisetu.authservice.dto.RoleAssignmentDTO;

import java.security.PrivateKey;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    private final PrivateKey privateKey;
    private final JwtProperties props;

    public JwtTokenProvider(PrivateKey privateKey, JwtProperties props) {
        this.privateKey = privateKey;
        this.props = props;
    }

    public String issueAccessToken(Long userId, String email, List<RoleAssignmentDTO> roles) {
        Date now = new Date();
        List<Map<String, Object>> roleClaims = roles.stream()
                .map(r -> {
                    // LinkedHashMap, not Map.of() — Map.of() forbids null values,
                    // which is exactly why the "" sentinel existed. Real nulls now.
                    Map<String, Object> claim = new LinkedHashMap<>();
                    claim.put("role", r.role());
                    claim.put("collegeId", r.collegeId()); // real Long, or real null — trust-wide roles get an actual null
                    claim.put("deptId", r.deptId());
                    return claim;
                })
                .toList();

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("roles", roleClaims)
                .issuer(props.getIssuer())
                .issuedAt(now)
                .expiration(new Date(now.getTime() + props.getAccessTokenTtlSeconds() * 1000))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }
}
