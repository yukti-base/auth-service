package org.yuktisetu.authservice.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                Claims claims = tokenProvider.verify(token);

                @SuppressWarnings("unchecked")
                List<Map<String, Object>> roleClaims = claims.get("roles", List.class);

                List<UserPrincipal.RoleClaim> roles = roleClaims.stream()
                        .map(m -> new UserPrincipal.RoleClaim(
                                (String) m.get("role"),
                                blankToNullUuid((String) m.get("collegeId")),
                                blankToNullUuid((String) m.get("deptId"))
                        ))
                        .toList();

                UserPrincipal principal = new UserPrincipal(
                        Long.parseLong(claims.getSubject()),
                        claims.get("email", String.class),
                        roles
                );

                List<GrantedAuthority> authorities = roles.stream()
                        .map(r -> new SimpleGrantedAuthority("ROLE_" + r.role()))
                        .map(GrantedAuthority.class::cast)
                        .toList();

                var authToken = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } catch (Exception e) {
                // Invalid/expired token: leave SecurityContext empty. Downstream
                // authorization will reject the request as unauthenticated —
                // do not throw here, or a single malformed header 500s the request
                // instead of cleanly 401ing it.
                SecurityContextHolder.clearContext();
            }
        }

        chain.doFilter(request, response);
    }

    private Long blankToNullUuid(String s) {
        return (s == null || s.isBlank()) ? null : Long.parseLong(s);
    }
}
