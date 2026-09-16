package org.yuktisetu.authservice.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yuktisetu.authservice.dto.AcceptInviteRequest;
import org.yuktisetu.authservice.dto.AcceptInviteResponse;
import org.yuktisetu.authservice.dto.CreateRoleUserRequest;
import org.yuktisetu.authservice.dto.DeactivateRoleRequest;
import org.yuktisetu.authservice.dto.HardDeleteRequest;
import org.yuktisetu.authservice.dto.SoftDeleteRequest;
import org.yuktisetu.authservice.service.RoleManagementService;
import org.yuktisetu.core.response.YuktiSetuResponse;
import org.yuktisetu.core.security.UserPrincipal;


@RestController
@RequestMapping("/roles")
@RequiredArgsConstructor
@Slf4j
public class RoleManagementController {
    private final RoleManagementService roleManagementService;

    // Parent-creates-child. Coarse role gate here is defense-in-depth only —
    // the real "can THIS role create THAT role" decision is RoleHierarchyPolicy,
    // inside the service. This annotation just keeps obviously-wrong callers
    // (a Student token, a Ground Volunteer token) from reaching the service at all.
    @PostMapping("/users")
    @PreAuthorize("hasAnyRole('TNP_SUPER_ADMIN','IT_ADMIN','TNP_COLLEGE_ADMIN','TNP_COORDINATOR','HOD')")
    public ResponseEntity<YuktiSetuResponse<Void>> createRoleUser(
            @AuthenticationPrincipal UserPrincipal actor,
            @RequestBody @Valid CreateRoleUserRequest request) {
        roleManagementService.createRoleUser(actor, request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(YuktiSetuResponse.success(null, HttpStatus.CREATED.value(), "Role user created"));
    }

    @PostMapping("/accept-invite")
    public ResponseEntity<YuktiSetuResponse<AcceptInviteResponse>> acceptInvite(@RequestBody @Valid AcceptInviteRequest request) {
        AcceptInviteResponse response = roleManagementService.acceptInvite(request);
        return ResponseEntity.ok(YuktiSetuResponse.success(response, "Invite accepted"));
    }

    @PostMapping("/deactivate")
    @PreAuthorize("hasAnyAuthority('ROLE_TNP_SUPER_ADMIN','ROLE_IT_ADMIN','ROLE_TNP_COLLEGE_ADMIN','ROLE_TNP_COORDINATOR','ROLE_HOD','ROLE_FACULTY_DEPT_COORDINATOR')")
    public ResponseEntity<YuktiSetuResponse<Void>> deactivate(
            @AuthenticationPrincipal UserPrincipal actor,
            @RequestBody @Valid DeactivateRoleRequest request) {
        roleManagementService.deactivateRoleAssignment(actor, request);
        return ResponseEntity.ok(YuktiSetuResponse.success(null, "Role deactivated"));
    }

    // The ordinary delete, and the only one any role-facing screen should call.
    // Reversible — the row stays, flagged. The service checks the actor's
    // authority over every role the target has ever held; this annotation is
    // only a coarse gate keeping obviously-wrong callers out.
    @PostMapping("/soft-delete")
    @PreAuthorize("hasAnyAuthority('ROLE_TNP_SUPER_ADMIN','ROLE_IT_ADMIN','ROLE_TNP_COLLEGE_ADMIN','ROLE_TNP_COORDINATOR','ROLE_HOD','ROLE_FACULTY_DEPT_COORDINATOR')")
    public ResponseEntity<YuktiSetuResponse<Void>> softDelete(
            @AuthenticationPrincipal UserPrincipal actor,
            @RequestBody @Valid SoftDeleteRequest request) {
        roleManagementService.softDeleteUser(actor, request);
        return ResponseEntity.ok(YuktiSetuResponse.success(null, "User deleted"));
    }

    // Hard delete gets its own path, not a DELETE verb on /users/{id} — an
    // irreversible, IT-Admin-only action deserves to be impossible to trigger
    // by a careless generic REST client hitting the "obvious" delete endpoint.
    // Unlike /soft-delete above, this one genuinely removes the row, and only
    // succeeds for an already-soft-deleted account with nothing referencing it.
    @PostMapping("/hard-delete")
    @PreAuthorize("hasAuthority('ROLE_IT_ADMIN')")
    public ResponseEntity<YuktiSetuResponse<Void>> hardDelete(
            @AuthenticationPrincipal UserPrincipal actor,
            @RequestBody @Valid HardDeleteRequest request) {
        roleManagementService.hardDeleteUser(actor, request);
        return ResponseEntity.ok(YuktiSetuResponse.success(null, "User permanently deleted"));
    }
}
