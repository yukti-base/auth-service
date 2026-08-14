package org.yuktisetu.authservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.stereotype.Component;
import org.yuktisetu.authservice.config.JwtProperties;
import org.yuktisetu.authservice.dto.RoleAssignmentDTO;
import org.yuktisetu.authservice.exception.AuthExceptions;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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

    /**
     * @return parsed claims.
     * @throws AuthExceptions.TokenExpiredException if the token is valid but expired — caller should attempt refresh.
     * @throws AuthExceptions.InvalidTokenException  if the token is malformed, unsupported, or fails signature
     *         verification — caller should force re-login; log this case, it's the forged/tampered path.
     */
    public Claims verify(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new AuthExceptions.TokenExpiredException(e);
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException e) {
            throw new AuthExceptions.InvalidTokenException(e);
        }
    }
}
