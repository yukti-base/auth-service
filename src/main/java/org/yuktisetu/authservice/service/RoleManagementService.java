package org.yuktisetu.authservice.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.yuktisetu.authservice.dto.AcceptInviteRequest;
import org.yuktisetu.authservice.dto.AcceptInviteResponse;
import org.yuktisetu.authservice.dto.CreateRoleUserRequest;
import org.yuktisetu.authservice.dto.DeactivateRoleRequest;
import org.yuktisetu.authservice.dto.HardDeleteRequest;
import org.yuktisetu.authservice.dto.SoftDeleteRequest;
import org.yuktisetu.authservice.exception.AuthExceptions;
import org.yuktisetu.authservice.policy.RoleHierarchyPolicy;
import org.yuktisetu.core.exception.NotFoundException;
import org.yuktisetu.core.notification.config.EmailProperties;
import org.yuktisetu.core.notification.model.EmailRequest;
import org.yuktisetu.core.notification.service.EmailService;
import org.yuktisetu.core.security.UserPrincipal;
import org.yuktisetu.db.College;
import org.yuktisetu.db.Department;
import org.yuktisetu.db.User;
import org.yuktisetu.db.UserRoleAssignment;
import org.yuktisetu.model.RoleType;
import org.yuktisetu.model.UserStatus;
import org.yuktisetu.repository.CollegeRepository;
import org.yuktisetu.repository.DepartmentRepository;
import org.yuktisetu.repository.DynamicFieldDefinitionRepository;
import org.yuktisetu.repository.StudentProfileRepository;
import org.yuktisetu.repository.UserRepository;
import org.yuktisetu.repository.UserRoleAssignmentRepository;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@AllArgsConstructor
@Slf4j
public class RoleManagementService {

    private final RoleHierarchyPolicy policy;
    private final InviteTokenService inviteTokenService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final UserRoleAssignmentRepository roleAssignmentRepository;
    private final StudentProfileRepository studentProfileRepository;
    private final DynamicFieldDefinitionRepository dynamicFieldDefinitionRepository;
    private final PasswordEncoder passwordEncoder;
    private final CollegeRepository collegeRepository;
    private final DepartmentRepository departmentRepository;
    private final EmailService emailService;
    private final EmailProperties emailProperties;

    /**
     * The single assignment an actor is acting from for one specific request:
     * which role, and at which college/dept that role is held. Carrying the
     * actor's OWN scope (not the target's) matters, because a College Admin
     * acting on a department holds college scope while the target is dept-scoped.
     */
    private record ActorRole(RoleType role, Long collegeId, Long deptId) {}

    @Transactional
    public void createRoleUser(UserPrincipal actor, CreateRoleUserRequest req) {
        // Shape-validate the target scope first, so an ill-formed request fails
        // the same way regardless of who sent it.
        validateScopeRequest(req.role(), req.collegeId(), req.deptId());

        ActorRole actorRole = resolveActorRole(actor, req.collegeId(), req.deptId());

        if (!policy.canCreate(actorRole.role(), req.role())) {
            log.warn("Role creation denied: actorId={}, actorRole={} may not create role={}",
                    actor.userId(), actorRole.role(), req.role());
            throw new AuthExceptions.InsufficientAuthorityException();
        }

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

        College college = null;
        if (policy.isCollegeScoped(req.role())) {
            college = collegeRepository.findById(req.collegeId())
                    .orElseThrow(() -> new NotFoundException("College not found for id: " + req.collegeId()));
        }

        Department department = null;
        if (policy.isDeptScoped(req.role())) {
            department = departmentRepository.findById(req.deptId())
                    .orElseThrow(() -> new NotFoundException("Department not found for id: " + req.deptId()));
        }

        User actorEntity = userRepository.getReferenceById(actor.userId());
        UserRoleAssignment assignment = UserRoleAssignment.builder()
                .user(newUser)
                .role(req.role())
                .college(college)
                .department(department)
                .isActive(true)
                .assignedAt(now)
                .assignedBy(actorEntity)
                .build();
        roleAssignmentRepository.save(assignment);

        log.info("Role user created: actorId={}, actorRole={}, actorCollegeId={}, newUserId={}, role={}, collegeId={}, deptId={}",
                actor.userId(), actorRole.role(), actorRole.collegeId(), newUser.getId(), req.role(), req.collegeId(), req.deptId());

        String token = inviteTokenService.issue(newUser.getId());
        String inviteLink = emailProperties.getBaseInviteUrl() + "?token=" + token;
        String fullName = newUser.getFirstName() + " " + newUser.getLastName();

        EmailRequest emailRequest = EmailRequest.builder()
            .to(List.of(newUser.getEmail()))
            .subject("You're invited to YuktiSetu")
            .templateName("invite-role-email")
            .templateVariables(Map.of(
                "inviteeName", fullName,
                "inviteLink", inviteLink
            ))
            .build();

        try {
            emailService.sendEmail(emailRequest);
            log.info("Invite email sent to {}", newUser.getEmail());
        } catch (Exception e) {
            log.error("Failed to send invite email to {}: {}", newUser.getEmail(), e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Invite issued for userId={}, email={}, token={}", newUser.getId(), newUser.getEmail(), token);
        }
    }

    @Transactional
    public AcceptInviteResponse acceptInvite(AcceptInviteRequest req) {
        Long userId = inviteTokenService.consume(req.token());
        if (userId == null) {
            log.warn("Invite acceptance failed: token invalid, expired, or already used");
            throw new AuthExceptions.InvalidInviteException();
        }

        User user = userRepository.findById(userId)
                .filter(u -> !u.isDeleted() && u.getStatus() == UserStatus.PENDING_ACTIVATION)
                .orElseThrow(() -> {
                    log.warn("Invite acceptance failed for userId={}: user not found or not pending activation", userId);
                    return new AuthExceptions.InvalidInviteException();
                });

        user.setPassword(passwordEncoder.encode(req.newPassword()));
        user.setStatus(UserStatus.ACTIVE);
        user.setUpdatedAt(new Date());
        userRepository.save(user);

        List<UserRoleAssignment> activeRoles = roleAssignmentRepository.findByUserIdAndIsActiveTrue(user.getId());

        // Highest-authority role decides what the client renders, for the same
        // reason resolveActorRole exists: never let list order decide.
        String role = activeRoles.stream()
                .map(UserRoleAssignment::getRole)
                .max(Comparator.comparingInt(policy::authorityRank))
                .map(RoleType::name)
                .orElse(RoleType.STUDENT.name());
        boolean isAdmin = !role.equals(RoleType.STUDENT.name());

        log.info("Invite accepted: userId={}, role={}", user.getId(), role);

        return new AcceptInviteResponse(role, isAdmin);
    }

    @Transactional
    public void deactivateRoleAssignment(UserPrincipal actor, DeactivateRoleRequest req) {
        // Same shape validation as creation: a trust-wide target must arrive
        // with null scope, a dept-scoped target with both ids.
        validateScopeRequest(req.targetRole(), req.collegeId(), req.deptId());

        ActorRole actorRole = resolveActorRole(actor, req.collegeId(), req.deptId());

        if (!policy.canDeactivate(actorRole.role(), req.targetRole())) {
            log.warn("Role deactivation denied: actorId={}, actorRole={} may not deactivate role={}",
                    actor.userId(), actorRole.role(), req.targetRole());
            throw new AuthExceptions.InsufficientAuthorityException();
        }

        if (policy.isTrustWide(req.targetRole())) {
            // Global last-one-standing guard: Super Admin / IT Admin, trust-wide,
            // no exceptions. Uses the IS NULL-aware count, not the derived query.
            long activeCount = roleAssignmentRepository.countActiveTrustWideHolders(req.targetRole());
            if (activeCount <= 1) {
                log.warn("Role deactivation denied: targetRole={} has only {} active holder(s) trust-wide",
                        req.targetRole(), activeCount);
                throw new AuthExceptions.LastActiveHolderException();
            }
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
                    if (childActive) {
                        log.warn("Role deactivation denied: targetRole={} is the last holder in collegeId={}, deptId={} with active subordinate role={}",
                                req.targetRole(), req.collegeId(), req.deptId(), child);
                        throw new AuthExceptions.LastActiveHolderException();
                    }
                }
            }
        }

        // IS NULL-aware for trust-wide targets; deliberately does NOT filter on
        // user status, since deactivating a role on an already-inactive account
        // is legitimate.
        UserRoleAssignment target = roleAssignmentRepository
                .findActiveAssignmentInScope(req.targetUserId(), req.targetRole(), req.collegeId(), req.deptId())
                .orElseThrow(() -> {
                    log.warn("Role deactivation failed: no active assignment for targetUserId={}, targetRole={}, collegeId={}, deptId={}",
                            req.targetUserId(), req.targetRole(), req.collegeId(), req.deptId());
                    return new AuthExceptions.NoActiveRoleException();
                });

        target.setActive(false);
        target.setRevokedAt(new Date());
        target.setRevokedBy(userRepository.getReferenceById(actor.userId()));
        roleAssignmentRepository.save(target);

        // Their authority just changed underneath them. Kill every live session so
        // the next login rebuilds claims from what they hold NOW. The already-issued
        // access token still lives out its <=15-minute TTL; that window is accepted
        // policy for role changes.
        long revoked = refreshTokenService.revokeAllForUser(req.targetUserId());

        log.info("Role deactivated: actorId={}, actorRole={}, targetUserId={}, targetRole={}, collegeId={}, deptId={}, sessionsRevoked={}",
                actor.userId(), actorRole.role(), req.targetUserId(), req.targetRole(), req.collegeId(), req.deptId(), revoked);
    }

    /**
     * The ordinary delete, and the only one any role-facing screen should call.
     * Reversible: the row stays, flagged. Permitted to any actor who could have
     * deactivated every role the target holds, checked at each role's own scope.
     */
    @Transactional
    public void softDeleteUser(UserPrincipal actor, SoftDeleteRequest req) {
        User target = userRepository.findById(req.targetUserId())
                .filter(u -> !u.isDeleted())
                .orElseThrow(AuthExceptions.AccountInactiveException::new);

        List<UserRoleAssignment> everyAssignment =
                roleAssignmentRepository.findAllByUser_Id(target.getId());

        // Must be fully deactivated first — soft delete is not a shortcut around
        // the last-holder-with-subordinates guard in deactivateRoleAssignment.
        boolean stillActive = everyAssignment.stream().anyMatch(UserRoleAssignment::isActive);
        if (stillActive) {
            log.warn("Soft delete denied: targetUserId={} still has active role assignment(s)", target.getId());
            throw new AuthExceptions.NotYetDeactivatedException();
        }

        // Authority is checked against every role the target has ever held, at
        // that role's own scope — not just against their most recent one.
        Set<RoleType> heldRoles = new LinkedHashSet<>(everyAssignment.stream().map(UserRoleAssignment::getRole).toList());
        if (heldRoles.isEmpty()) {
            // An account that never received an assignment (created, then abandoned).
            // Treat it as a trust-wide action so only the top two roles may clear it.
            ActorRole actorRole = resolveActorRole(actor, null, null);
            if (actorRole.role() != RoleType.IT_ADMIN && actorRole.role() != RoleType.TNP_SUPER_ADMIN) {
                throw new AuthExceptions.InsufficientAuthorityException();
            }
        } else {
            for (UserRoleAssignment a : everyAssignment) {
                ActorRole actorRole = resolveActorRole(actor, a.getCollegeId(), a.getDeptId());
                if (!policy.canDeactivate(actorRole.role(), a.getRole())) {
                    log.warn("Soft delete denied: actorId={}, actorRole={} may not act on target role={} at collegeId={}, deptId={}",
                            actor.userId(), actorRole.role(), a.getRole(), a.getCollegeId(), a.getDeptId());
                    throw new AuthExceptions.InsufficientAuthorityException();
                }
            }
        }

        Date now = new Date();
        target.setDeleted(true);
        target.setDeletedAt(now);
        target.setDeletedBy(actor.userId());
        target.setStatus(UserStatus.INACTIVE);
        target.setUpdatedAt(now);
        userRepository.save(target);

        long revoked = refreshTokenService.revokeAllForUser(target.getId());

        log.info("User soft-deleted: actorId={}, targetUserId={}, rolesHeld={}, sessionsRevoked={}",
                actor.userId(), target.getId(), heldRoles, revoked);
    }

    /**
     * Permanent removal of the row. IT Admin only, and deliberately hard to
     * reach: the account must already be soft-deleted, and nothing may still
     * reference it.
     *
     * User.roleAssignments is mapped CascadeType.ALL, so a bare delete() would
     * silently take the target's entire role history with it — including the
     * assigned_by / revoked_by trail of actions they performed on other people.
     * Every guard below refuses rather than cascading, which is the stated rule:
     * an entity with connected children is not deletable. In practice this
     * reserves hard delete for accounts created in error that never did
     * anything, which is the only case where it is actually safe.
     */
    @Transactional
    public void hardDeleteUser(UserPrincipal actor, HardDeleteRequest req) {
        ActorRole actorRole = resolveActorRole(actor, null, null);
        if (actorRole.role() != RoleType.IT_ADMIN) {
            log.warn("Hard delete denied: actorId={} is not IT_ADMIN (resolved role={})", actor.userId(), actorRole.role());
            throw new AuthExceptions.InsufficientAuthorityException();
        }

        if (actor.userId().equals(req.targetUserId())) {
            log.warn("Hard delete denied: actorId={} attempted to delete their own account", actor.userId());
            throw new AuthExceptions.InsufficientAuthorityException();
        }

        User target = userRepository.findById(req.targetUserId())
                .orElseThrow(() -> new NotFoundException("User not found for id: " + req.targetUserId()));

        if (!target.isDeleted()) {
            log.warn("Hard delete denied: targetUserId={} is not soft-deleted yet", target.getId());
            throw new AuthExceptions.NotSoftDeletedException();
        }

        List<String> blockers = new ArrayList<>();

        long ownAssignments = roleAssignmentRepository.countByUser_Id(target.getId());
        if (ownAssignments > 0) {
            blockers.add(ownAssignments + " role assignment(s)");
        }
        long assignedByCount = roleAssignmentRepository.countByAssignedBy_Id(target.getId());
        if (assignedByCount > 0) {
            blockers.add("assigned " + assignedByCount + " role(s) to other users");
        }
        long revokedByCount = roleAssignmentRepository.countByRevokedBy_Id(target.getId());
        if (revokedByCount > 0) {
            blockers.add("revoked " + revokedByCount + " role(s) from other users");
        }
        long deletedOthers = userRepository.countByDeletedBy(target.getId());
        if (deletedOthers > 0) {
            blockers.add("soft-deleted " + deletedOthers + " other user(s)");
        }
        long fieldsCreated = dynamicFieldDefinitionRepository.countByCreatedByUser_Id(target.getId());
        if (fieldsCreated > 0) {
            blockers.add("created " + fieldsCreated + " dynamic field definition(s)");
        }
        if (studentProfileRepository.existsByUser_Id(target.getId())) {
            blockers.add("owns a student profile");
        }

        if (!blockers.isEmpty()) {
            String detail = String.join("; ", blockers);
            log.warn("Hard delete blocked for targetUserId={}: {}", target.getId(), detail);
            throw new AuthExceptions.CascadeBlockedException(detail);
        }

        refreshTokenService.revokeAllForUser(target.getId());
        userRepository.delete(target);

        log.warn("User PERMANENTLY deleted: actorId={}, targetUserId={}, email={}",
                actor.userId(), target.getId(), target.getEmail());
    }

    /**
     * Decides which of an actor's roles this request is being made with.
     *
     * This was previously {@code actor.roles().stream().findFirst()}, which took
     * whichever claim the JWT happened to list first — an unordered result set.
     * For anyone holding two different roles that made their effective authority
     * non-deterministic between logins.
     *
     * The rule now, in order:
     *   1. A claim is APPLICABLE if it is trust-wide (null college), or its
     *      college matches the college being acted on; and, if the claim itself
     *      is dept-scoped, its dept matches too. A claim whose scope is broader
     *      than the target (College Admin acting on a dept) is applicable; one
     *      that is narrower, or belongs to a different college, is not.
     *   2. Among applicable claims the highest authorityRank wins, with the role
     *      name as a stable tie-break, so the outcome never depends on order.
     *   3. The winner is re-verified against the database through
     *      findLiveActorAssignment, which requires the assignment to still be
     *      active AND the account to be onboarded (status ACTIVE, not deleted).
     *      The JWT can be up to 15 minutes stale; the database cannot.
     */
    private ActorRole resolveActorRole(UserPrincipal actor, Long targetCollegeId, Long targetDeptId) {
        if (actor == null || actor.roles() == null || actor.roles().isEmpty()) {
            throw new AuthExceptions.NoActiveRoleException();
        }

        ActorRole candidate = actor.roles().stream()
                .filter(claim -> isApplicable(claim, targetCollegeId, targetDeptId))
                .map(claim -> new ActorRole(RoleType.valueOf(claim.role()), claim.collegeId(), claim.deptId()))
                .max(Comparator.comparingInt((ActorRole a) -> policy.authorityRank(a.role()))
                        .thenComparing(a -> a.role().name()))
                .orElseThrow(() -> {
                    log.warn("Actor role resolution failed: actorId={} holds no role applicable to collegeId={}, deptId={}",
                            actor.userId(), targetCollegeId, targetDeptId);
                    return new AuthExceptions.ScopeViolationException();
                });

        roleAssignmentRepository
                .findLiveActorAssignment(actor.userId(), candidate.role(), candidate.collegeId(), candidate.deptId())
                .orElseThrow(() -> {
                    log.warn("Actor role resolution rejected: actorId={} presented role={} at collegeId={}, deptId={} which is no longer live",
                            actor.userId(), candidate.role(), candidate.collegeId(), candidate.deptId());
                    return new AuthExceptions.NoActiveRoleException();
                });

        return candidate;
    }

    /**
     * Is this claim usable for an action aimed at the given college/dept?
     *
     * A trust-wide claim (null college, null dept) reaches everywhere. A
     * college-scoped claim reaches only its own college, at any depth within it.
     * A dept-scoped claim reaches only its own department.
     */
    private boolean isApplicable(UserPrincipal.RoleClaim claim, Long targetCollegeId, Long targetDeptId) {
        if (claim.collegeId() != null && !claim.collegeId().equals(targetCollegeId)) {
            return false;
        }
        return claim.deptId() == null || claim.deptId().equals(targetDeptId);
    }

    private void validateScopeRequest(RoleType role, Long collegeId, Long deptId) {
        if (policy.isCollegeScoped(role) && collegeId == null)
            throw new AuthExceptions.BadCredentialsExceptions("collegeId required for " + role);
        if (policy.isDeptScoped(role) && deptId == null)
            throw new AuthExceptions.BadCredentialsExceptions("deptId required for " + role);
        if (policy.isTrustWide(role) && (collegeId != null || deptId != null))
            throw new AuthExceptions.BadCredentialsExceptions(role + " is trust-wide, scope must be null");
    }
}
