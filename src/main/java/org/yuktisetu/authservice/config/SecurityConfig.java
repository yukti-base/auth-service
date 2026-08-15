package org.yuktisetu.authservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;
import org.yuktisetu.core.security.JwtAuthenticationFilter;
import org.yuktisetu.core.security.JwtTokenVerifier;
import org.yuktisetu.core.security.RestAccessDeniedHandler;
import org.yuktisetu.core.security.RestAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Strength 12 — deliberately above the BCrypt default of 10. This service
        // authenticates every role up to Super Admin/IT Admin; the extra hashing
        // cost (still well under 100ms) is worth it for accounts that hold
        // trust-wide access.
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtTokenVerifier tokenVerifier, CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // stateless bearer-token API, no cookies/sessions to protect
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .sessionManagement(sm ->
                    sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/register", "/refresh", "/actuator/health").permitAll()
                .requestMatchers("/roles/accept-invite").permitAll()
                .requestMatchers("/roles/**").authenticated()
                .anyRequest().authenticated()
            )
            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                    .accessDeniedHandler(new RestAccessDeniedHandler())
            )
            .addFilterBefore(
                    new JwtAuthenticationFilter(tokenVerifier),
                    UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }
}
