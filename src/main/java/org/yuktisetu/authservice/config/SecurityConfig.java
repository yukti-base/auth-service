package org.yuktisetu.authservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfigurationSource;
import org.yuktisetu.core.security.JwtAuthenticationFilter;
import org.yuktisetu.core.security.JwtTokenVerifier;
import org.yuktisetu.core.security.RestAccessDeniedHandler;
import org.yuktisetu.core.security.RestAuthenticationEntryPoint;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private static final List<String> ALLOWED_CONNECT_SRC = List.of(
            "'self'",
            "https://hoppscotch.io",
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:8081",
            "http://localhost:8083"
    );

    private static final String CSP_POLICY = "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src " + String.join(" ", ALLOWED_CONNECT_SRC) + "; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'";

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtTokenVerifier tokenVerifier, CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .sessionManagement(sm ->
                    sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/login", "/register", "/refresh", "/actuator/health").permitAll()
                .requestMatchers("/roles/accept-invite").permitAll()
                .requestMatchers("/roles/**").authenticated()
                .anyRequest().authenticated()
            )
            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                    .accessDeniedHandler(new RestAccessDeniedHandler())
            )
            .headers(headers -> headers
                    .contentSecurityPolicy(csp -> csp.policyDirectives(CSP_POLICY))
                    .contentTypeOptions(contentTypeOptions -> contentTypeOptions.disable())
                    .frameOptions(frameOptions -> frameOptions.deny())
                    .referrerPolicy(referrerPolicy -> referrerPolicy.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                    .addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"))
                    .addHeaderWriter(new StaticHeadersWriter("X-Frame-Options", "DENY"))
                    .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy", "geolocation=(), microphone=(), camera=()"))
            )
            .addFilterBefore(
                    new JwtAuthenticationFilter(tokenVerifier),
                    UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }
}
