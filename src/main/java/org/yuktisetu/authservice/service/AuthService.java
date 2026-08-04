package org.yuktisetu.authservice.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.yuktisetu.authservice.dto.LoginRequest;
import org.yuktisetu.authservice.dto.LoginResponse;
import org.yuktisetu.authservice.dto.RegisterRequest;
import org.yuktisetu.authservice.dto.RegisterResponse;
import org.yuktisetu.authservice.dto.RoleAssignmentDTO;
import org.yuktisetu.authservice.exception.AuthExceptions.AccountInactiveException;
import org.yuktisetu.authservice.exception.AuthExceptions.InvalidCredentialsException;
import org.yuktisetu.authservice.exception.AuthExceptions.NoActiveRoleException;
import org.yuktisetu.authservice.exception.AuthExceptions.UserAlreadyExistsException;
import org.yuktisetu.authservice.config.JwtProperties;
import org.yuktisetu.authservice.security.JwtTokenProvider;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.yuktisetu.db.User;
import org.yuktisetu.db.UserRoleAssignment;
import org.yuktisetu.model.UserStatus;
import org.yuktisetu.repository.UserRepository;
import org.yuktisetu.repository.UserRoleAssignmentRepository;

import java.util.Date;
import java.util.List;

@Service
@AllArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final UserRoleAssignmentRepository roleAssignmentRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final LoginAttemptService loginAttemptService;
    private final JwtProperties jwtProperties;

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        String email = request.email().trim().toLowerCase();
        String phone = request.phone().trim();
        Date now = new Date();

        if (userRepository.existsByEmailIgnoreCaseAndIsDeletedFalse(email)) {
            throw new UserAlreadyExistsException();
        }

        User user = User.builder()
                .email(email)
                .phone(phone)
                .password(passwordEncoder.encode(request.password()))
                .status(UserStatus.ACTIVE)
                .createdAt(now)
                .updatedAt(now)
                .isDeleted(false)
                .build();

        UserRoleAssignment roleAssignment = UserRoleAssignment.builder()
                .user(user)
                .role(request.role())
                .isActive(true)
                .assignedAt(now)
                .assignedBy(user)
                .build();

        try {
            User savedUser = userRepository.save(user);
            roleAssignmentRepository.save(roleAssignment);

            List<RoleAssignmentDTO> roleDtos = List.of(new RoleAssignmentDTO(
                    request.role().name(),
                    roleAssignment.getCollegeId(),
                    roleAssignment.getDeptId()
            ));
            String accessToken = jwtTokenProvider.issueAccessToken(savedUser.getId(), savedUser.getEmail(), roleDtos);

            return new RegisterResponse(
                    savedUser.getId(),
                    savedUser.getEmail(),
                    savedUser.getPhone(),
                    savedUser.getStatus(),
                    request.role().name(),
                    accessToken
            );
        } catch (DataIntegrityViolationException ex) {
            if (isDuplicateUserViolation(ex)) {
                throw new UserAlreadyExistsException();
            }
            throw ex;
        }
    }

    private boolean isDuplicateUserViolation(DataIntegrityViolationException ex) {
        String message = ex.getMostSpecificCause() == null ? ex.getMessage() : ex.getMostSpecificCause().getMessage();
        if (message == null) {
            return false;
        }
        String normalized = message.toLowerCase();
        return normalized.contains("duplicate")
                || normalized.contains("unique constraint")
                || normalized.contains("users_email")
                || normalized.contains("users_phone");
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        String email = request.email().trim().toLowerCase();

        // Lockout check happens BEFORE touching the DB — cheap Redis read protects
        // against hammering Postgres with a brute-force flood too.
        loginAttemptService.assertNotLocked(email);

        User user = userRepository.findByEmailIgnoreCaseAndIsDeletedFalse(email)
                .orElseGet(() -> {
                    // Still record a failure against the attempted email even though
                    // no such user exists — otherwise an attacker can distinguish
                    // "wrong password" from "no such account" by which one skips
                    // the lockout counter, defeating the point of the check above.
                    loginAttemptService.recordFailure(email);
                    throw new InvalidCredentialsException();
                });

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            loginAttemptService.recordFailure(email);
            throw new InvalidCredentialsException();
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AccountInactiveException();
        }

        List<UserRoleAssignment> activeRoles = roleAssignmentRepository.findByUserIdAndIsActiveTrue(user.getId());
        if (activeRoles.isEmpty()) {
            // A credentialed-but-roleless account (e.g. mid-offboarding, revoked
            // but not yet deleted) must not be able to log in and hold a token
            // that grants zero access but still "looks" authenticated to clients.
            throw new NoActiveRoleException();
        }

        List<RoleAssignmentDTO> roleDtos = activeRoles.stream()
                .map(r -> new RoleAssignmentDTO(r.getRole().name(), r.getCollegeId(), r.getDeptId()))
                .toList();

        loginAttemptService.recordSuccess(email);
        user.setLastLoginAt(new Date());
        userRepository.save(user);

        String accessToken = jwtTokenProvider.issueAccessToken(user.getId(), user.getEmail(), roleDtos);
        String refreshToken = refreshTokenService.issue(user.getId());

        return new LoginResponse(
                accessToken,
                refreshToken,
                jwtProperties.getAccessTokenTtlSeconds(),
                user.getId(),
                user.getEmail(),
                roleDtos
        );
    }

    @Transactional
    public LoginResponse refresh(String refreshToken) {
        Long userId = refreshTokenService.consume(refreshToken); // single-use: dead the moment it's read

        User user = userRepository.findById(userId)
                .filter(u -> !u.isDeleted())
                .orElseThrow(AccountInactiveException::new);

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AccountInactiveException();
        }

        List<UserRoleAssignment> activeRoles = roleAssignmentRepository.findByUserIdAndIsActiveTrue(user.getId());
        if (activeRoles.isEmpty()) {
            throw new NoActiveRoleException();
        }

        List<RoleAssignmentDTO> roleDtos = activeRoles.stream()
                .map(r -> new RoleAssignmentDTO(r.getRole().name(), r.getCollegeId(), r.getDeptId()))
                .toList();

        String newAccessToken = jwtTokenProvider.issueAccessToken(user.getId(), user.getEmail(), roleDtos);
        String newRefreshToken = refreshTokenService.issue(user.getId());

        return new LoginResponse(newAccessToken, newRefreshToken, jwtProperties.getAccessTokenTtlSeconds(),
                user.getId(), user.getEmail(), roleDtos);
    }

    public void logout(String refreshToken) {
        refreshTokenService.revoke(refreshToken);
    }
}
