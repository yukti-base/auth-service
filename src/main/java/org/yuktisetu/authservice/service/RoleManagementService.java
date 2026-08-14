package org.yuktisetu.authservice.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.yuktisetu.authservice.dto.AcceptInviteRequest;
import org.yuktisetu.authservice.dto.CreateRoleUserRequest;
import org.yuktisetu.authservice.dto.DeactivateRoleRequest;
import org.yuktisetu.authservice.dto.HardDeleteRequest;
import org.yuktisetu.authservice.exception.AuthExceptions;
import org.yuktisetu.authservice.policy.RoleHierarchyPolicy;
import org.yuktisetu.authservice.security.UserPrincipal;
import org.yuktisetu.db.User;
import org.yuktisetu.db.UserRoleAssignment;
import org.yuktisetu.model.RoleType;
import org.yuktisetu.model.UserStatus;
import org.yuktisetu.repository.UserRepository;
import org.yuktisetu.repository.UserRoleAssignmentRepository;

import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
@AllArgsConstructor
@Slf4j
public class RoleManagementService {

    private final RoleHierarchyPolicy policy;
    private final InviteTokenService inviteTokenService;
    private final UserRepository userRepository;
    private final UserRoleAssignmentRepository roleAssignmentRepository;
    private final PasswordEncoder passwordEncoder;
//    private final NotificationClient notificationClient; // stub interface — wire to your Kafka producer for the Notification Service

    @Transactional
    public void createRoleUser(UserPrincipal actor, CreateRoleUserRequest req) {
        RoleType actorRole = primaryActorRole(actor); // see helper below — actor should have exactly one active role, per your no-multi-role rule
        if (!policy.canCreate(actorRole, req.role())) {
            throw new AuthExceptions.InsufficientAuthorityException();
        }

// --- Target-role scope shape validation (does the ROLE BEING CREATED
        // have the collegeId/deptId it requires, and nothing extra) ---
//        validateScopeRequest(req.role(), req.collegeId(), req.deptId());

        // --- Actor-scope containment check (is the ACTOR authorized to act
        // at the location they're requesting, regardless of what role they're
        // creating) ---
//        if (!policy.isTrustWide(actorRole)) {
//            boolean inScope;
//            if (policy.isDeptScoped(actorRole)) {
//                // HoD (or any future dept-scoped creator) — authority stops at their own dept
//                inScope = req.deptId() != null && roleAssignmentRepository
//                        .(actor.userId(), actorRole, req.deptId());
//            } else if (policy.isCollegeScoped(actorRole)) {
//                // College Admin / TnP Coordinator — authority covers the whole college, any dept within it
//                inScope = req.collegeId() != null && roleAssignmentRepository
//                        .existsByUserIdAndRoleAndCollegeIdAndIsActiveTrue(actor.userId(), actorRole, req.collegeId());
//            } else {
//                inScope = false; // unrecognized scope shape — fail closed, don't default to allow
//            }
//            if (!inScope) throw new AuthExceptions.ScopeViolationException();
//        }

        if (userRepository.existsByEmailIgnoreCaseAndIsDeletedFalse(req.email().trim().toLowerCase())) {
            throw new AuthExceptions.UserAlreadyExistsException();
        }

        Date now = new Date();
        User newUser = User.builder()
                .email(req.email().trim().toLowerCase())
                .phone(req.phone().trim())
                .firstName(req.firstName())
                .lastName(req.lastName())
                .password(passwordEncoder.encode(req.firstName().concat(req.email().substring(0, Math.min(4, req.email().length()))))) // unusable placeholder — real password set on invite accept
                .status(UserStatus.PENDING_ACTIVATION)
                .createdAt(now)
                .updatedAt(now)
                .isDeleted(false)
                .build();
        userRepository.save(newUser);

        User actorEntity = userRepository.getReferenceById(actor.userId());
        UserRoleAssignment assignment = UserRoleAssignment.builder()
                .user(newUser)
                .role(req.role())
                .college(null)  // TODO: connect proper ids here
                .department(null)
                .isActive(true)
                .assignedAt(now)
                .assignedBy(actorEntity)
                .build();
        roleAssignmentRepository.save(assignment);

        String token = inviteTokenService.issue(newUser.getId());
//        notificationClient.sendInviteEmail(newUser.getEmail(), newUser.getFirstName().concat(" ").concat(newUser.getLastName()), token);
        if (log.isDebugEnabled()) {
            log.debug("Invite issued for userId={}, email={}, token={} (DEV ONLY — never logs at this level in prod)",
                    newUser.getId(), newUser.getEmail(), token);
        }
    }

    @Transactional
    public void acceptInvite(AcceptInviteRequest req) {
        Long userId = inviteTokenService.consume(req.token());
        if (userId == null) throw new AuthExceptions.InvalidInviteException();

        User user = userRepository.findById(userId)
                .filter(u -> !u.isDeleted() && u.getStatus() == UserStatus.PENDING_ACTIVATION)
                .orElseThrow(AuthExceptions.InvalidInviteException::new);

        user.setPassword(passwordEncoder.encode(req.newPassword()));
        user.setStatus(UserStatus.ACTIVE);
        user.setUpdatedAt(new Date());
        userRepository.save(user);
    }

    @Transactional
    public void deactivateRoleAssignment(UserPrincipal actor, DeactivateRoleRequest req) {
        RoleType actorRole = primaryActorRole(actor);
        if (!policy.canDeactivate(actorRole, req.targetRole())) {
            throw new AuthExceptions.InsufficientAuthorityException();
        }
        if (policy.isCollegeScoped(req.targetRole()) && !policy.isTrustWide(actorRole)) {
            boolean inScope = roleAssignmentRepository
                    .existsByUserIdAndRoleAndCollegeIdAndIsActiveTrue(actor.userId(), actorRole, req.collegeId());
            if (!inScope) throw new AuthExceptions.ScopeViolationException();
        }

        // Global last-one-standing guard: Super Admin / IT Admin, trust-wide, no exceptions.
        if (req.targetRole() == RoleType.TNP_SUPER_ADMIN || req.targetRole() == RoleType.IT_ADMIN) {
            long activeCount = roleAssignmentRepository.countByRoleAndIsActiveTrue(req.targetRole());
            if (activeCount <= 1) throw new AuthExceptions.LastActiveHolderException();
        } else {
            // Scoped last-holder-with-live-subordinates guard.
            long remainingHolders = policy.isDeptScoped(req.targetRole())
                    ? roleAssignmentRepository.countByRoleAndCollegeIdAndDepartmentIdAndIsActiveTrue(req.targetRole(), req.collegeId(), req.deptId())
                    : roleAssignmentRepository.countByRoleAndCollegeIdAndIsActiveTrue(req.targetRole(), req.collegeId());

            if (remainingHolders <= 1) {
                for (RoleType child : policy.childrenOf(req.targetRole())) {
                    boolean childActive = policy.isDeptScoped(child)
                            ? roleAssignmentRepository.existsByRoleAndCollegeIdAndDepartmentIdAndIsActiveTrue(child, req.collegeId(), req.deptId())
                            : roleAssignmentRepository.existsByRoleAndCollegeIdAndIsActiveTrue(child, req.collegeId());
                    if (childActive) throw new AuthExceptions.LastActiveHolderException();
                }
            }
        }

        UserRoleAssignment target = roleAssignmentRepository
                .findByUserIdAndRoleAndCollegeIdAndDepartmentIdAndIsActiveTrue(req.targetUserId(), req.targetRole(), req.collegeId(), req.deptId());

        if (Objects.isNull(target)) {
            throw new AuthExceptions.NoActiveRoleException();
        }
        target.setActive(false);
        target.setRevokedAt(new Date());
        target.setRevokedBy(userRepository.getReferenceById(actor.userId()));
        roleAssignmentRepository.save(target);
    }

    @Transactional
    public void hardDeleteUser(UserPrincipal actor, HardDeleteRequest req) {
        if (primaryActorRole(actor) != RoleType.IT_ADMIN) {
            throw new AuthExceptions.InsufficientAuthorityException();
        }

        User target = userRepository.findById(req.targetUserId())
                .filter(u -> !u.isDeleted())
                .orElseThrow(AuthExceptions.AccountInactiveException::new);

        List<UserRoleAssignment> allAssignments = roleAssignmentRepository.findByUserIdAndIsActiveTrue(target.getId());
        if (!allAssignments.isEmpty()) {
            // universal precondition, not just College Admin — see note below
            throw new AuthExceptions.NotYetDeactivatedException();
        }

        target.setDeleted(true);
        target.setDeletedAt(new Date());
        target.setDeletedBy(actor.userId());
        userRepository.save(target);
    }

    private RoleType primaryActorRole(UserPrincipal actor) {
        // Enforces your one-role-per-person rule at the call site — if this ever
        // returns more than one distinct role, something upstream is broken.
        return actor.roles().stream()
                .map(UserPrincipal.RoleClaim::role)
                .map(RoleType::valueOf)
                .findFirst()
                .orElseThrow(AuthExceptions.NoActiveRoleException::new);
    }

//    private void validateScopeRequest(RoleType role, Long collegeId, Long deptId) {
//        if (policy.isCollegeScoped(role) && collegeId == null)
//            throw new AuthExceptions.InvalidScopeRequestException("collegeId required for " + role);
//        if (policy.isDeptScoped(role) && deptId == null)
//            throw new AuthExceptions.InvalidScopeRequestException("deptId required for " + role);
//        if (policy.isTrustWide(role) && (collegeId != null || deptId != null))
//            throw new AuthExceptions.InvalidScopeRequestException(role + " is trust-wide, scope must be null");
//    }
}
