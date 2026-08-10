package org.yuktisetu.authservice.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yuktisetu.authservice.dto.AcceptInviteRequest;
import org.yuktisetu.authservice.dto.CreateRoleUserRequest;
import org.yuktisetu.authservice.dto.DeactivateRoleRequest;
import org.yuktisetu.authservice.dto.HardDeleteRequest;
import org.yuktisetu.authservice.security.UserPrincipal;
import org.yuktisetu.authservice.service.RoleManagementService;


@RestController
@RequestMapping("/roles")
@RequiredArgsConstructor
public class RoleManagementController {
    private final RoleManagementService roleManagementService;

    // Parent-creates-child. Coarse role gate here is defense-in-depth only —
    // the real "can THIS role create THAT role" decision is RoleHierarchyPolicy,
    // inside the service. This annotation just keeps obviously-wrong callers
    // (a Student token, a Ground Volunteer token) from reaching the service at all.
    @PostMapping("/users")
    @PreAuthorize("hasAnyRole('TNP_SUPER_ADMIN','IT_ADMIN','TNP_COLLEGE_ADMIN','TNP_COORDINATOR','HOD')")
    public ResponseEntity<Void> createRoleUser(
            @AuthenticationPrincipal UserPrincipal actor,
            @RequestBody @Valid CreateRoleUserRequest request) {
        roleManagementService.createRoleUser(actor, request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    // Deliberately NOT behind @PreAuthorize / no JWT required — the caller has
    // no account yet at this point, only the invite token, which IS the credential.
    @PostMapping("/accept-invite")
    public ResponseEntity<Void> acceptInvite(@RequestBody @Valid AcceptInviteRequest request) {
        roleManagementService.acceptInvite(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/deactivate")
    @PreAuthorize("hasAnyAuthority('ROLE_TNP_SUPER_ADMIN','ROLE_IT_ADMIN','ROLE_TNP_COLLEGE_ADMIN','ROLE_TNP_COORDINATOR','ROLE_HOD','ROLE_FACULTY_DEPT_COORDINATOR')")
    public ResponseEntity<Void> deactivate(
            @AuthenticationPrincipal UserPrincipal actor,
            @RequestBody @Valid DeactivateRoleRequest request) {
        roleManagementService.deactivateRoleAssignment(actor, request);
        return ResponseEntity.ok().build();
    }

    // Hard delete gets its own path, not a DELETE verb on /users/{id} — an
    // irreversible, IT-Admin-only action deserves to be impossible to trigger
    // by a careless generic REST client hitting the "obvious" delete endpoint.
    @PostMapping("/hard-delete")
    @PreAuthorize("hasAuthority('ROLE_IT_ADMIN')")
    public ResponseEntity<Void> hardDelete(
            @AuthenticationPrincipal UserPrincipal actor,
            @RequestBody @Valid HardDeleteRequest request) {
        roleManagementService.hardDeleteUser(actor, request);
        return ResponseEntity.noContent().build();
    }
}
