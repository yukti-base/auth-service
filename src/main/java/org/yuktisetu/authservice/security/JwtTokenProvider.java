package org.yuktisetu.authservice.security;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.stereotype.Component;
import org.yuktisetu.authservice.config.JwtProperties;
import org.yuktisetu.authservice.dto.RoleAssignmentDTO;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final JwtProperties props;

    public JwtTokenProvider(PrivateKey privateKey, PublicKey publicKey, JwtProperties props) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.props = props;
    }

    public String issueAccessToken(Long userId, String email, List<RoleAssignmentDTO> roles) {
        Date now = new Date();
        List<Map<String, Object>> roleClaims = roles.stream()
                .map(r -> Map.<String, Object>of(
                        "role", r.role(),
                        "collegeId", r.collegeId() == null ? "" : r.collegeId().toString(),
                        "deptId", r.deptId() == null ? "" : r.deptId().toString()
                ))
                .toList();

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("roles", roleClaims)
                .issuer(props.getIssuer())
                .issuedAt(now)
                .expiration(new Date(now.getTime() + props.getAccessTokenTtlSeconds() * 1000))
                .id(UUID.randomUUID().toString()) // jti — lets downstream services log/trace a specific token if needed
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    /**
     * @return parsed claims, or throws if the token is expired/malformed/forged.
     */
    public Claims verify(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (SignatureException e) {
            throw new IllegalArgumentException("Token signature invalid", e);
        }
    }
}
