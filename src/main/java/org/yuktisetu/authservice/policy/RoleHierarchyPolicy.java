package org.yuktisetu.authservice.policy;

import org.springframework.stereotype.Component;
import org.yuktisetu.model.RoleType;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import static org.yuktisetu.model.RoleType.*;

@Component
public class RoleHierarchyPolicy {
    // Who is allowed to CREATE which target role.
    private static final Map<RoleType, Set<RoleType>> CAN_CREATE = new EnumMap<>(RoleType.class);
    static {
        CAN_CREATE.put(TNP_SUPER_ADMIN, EnumSet.of(TNP_SUPER_ADMIN, IT_ADMIN, TNP_COLLEGE_ADMIN, HOD));
        CAN_CREATE.put(IT_ADMIN, EnumSet.of(TNP_SUPER_ADMIN, IT_ADMIN, TNP_COLLEGE_ADMIN, HOD, TNP_COORDINATOR, STUDENT, GROUND_VOLUNTEER, FACULTY_DEPT_COORDINATOR));
        CAN_CREATE.put(TNP_COLLEGE_ADMIN, EnumSet.of(TNP_COORDINATOR, HOD));
        CAN_CREATE.put(TNP_COORDINATOR, EnumSet.of(HOD, GROUND_VOLUNTEER));
        CAN_CREATE.put(HOD, EnumSet.of(FACULTY_DEPT_COORDINATOR, STUDENT));
        CAN_CREATE.put(FACULTY_DEPT_COORDINATOR, EnumSet.of(STUDENT)); // students come via bulk upload, not this flow
    }

    // Who is allowed to DEACTIVATE which target role. (Hard-delete is separate — IT_ADMIN only, everywhere.)
    private static final Map<RoleType, Set<RoleType>> CAN_DEACTIVATE = new EnumMap<>(RoleType.class);
    static {
        CAN_DEACTIVATE.put(STUDENT, EnumSet.of(FACULTY_DEPT_COORDINATOR, HOD, TNP_COORDINATOR, TNP_COLLEGE_ADMIN, TNP_SUPER_ADMIN));
        CAN_DEACTIVATE.put(FACULTY_DEPT_COORDINATOR, EnumSet.of(HOD, TNP_COORDINATOR, TNP_COLLEGE_ADMIN, TNP_SUPER_ADMIN));
        CAN_DEACTIVATE.put(GROUND_VOLUNTEER, EnumSet.of(TNP_COORDINATOR, TNP_COLLEGE_ADMIN, TNP_SUPER_ADMIN));
        CAN_DEACTIVATE.put(TNP_COORDINATOR, EnumSet.of(TNP_COLLEGE_ADMIN, TNP_SUPER_ADMIN));
        CAN_DEACTIVATE.put(TNP_COLLEGE_ADMIN, EnumSet.of(TNP_SUPER_ADMIN));
        CAN_DEACTIVATE.put(TNP_SUPER_ADMIN, EnumSet.of(IT_ADMIN));
        CAN_DEACTIVATE.put(IT_ADMIN, EnumSet.of(TNP_SUPER_ADMIN));
        CAN_DEACTIVATE.put(HOD, EnumSet.of(TNP_COORDINATOR, TNP_COLLEGE_ADMIN, TNP_SUPER_ADMIN));
    }

    // Immediate child role(s) below a given role — used only for the
    // "last active holder with live subordinates" deactivation guard.
    private static final Map<RoleType, Set<RoleType>> CHILDREN = new EnumMap<>(RoleType.class);
    static {
        CHILDREN.put(TNP_SUPER_ADMIN, EnumSet.of(TNP_COLLEGE_ADMIN));
        CHILDREN.put(TNP_COLLEGE_ADMIN, EnumSet.of(TNP_COORDINATOR));
        CHILDREN.put(TNP_COORDINATOR, EnumSet.of(HOD, GROUND_VOLUNTEER));
        CHILDREN.put(HOD, EnumSet.of(FACULTY_DEPT_COORDINATOR));
        CHILDREN.put(FACULTY_DEPT_COORDINATOR, EnumSet.of(STUDENT));
        CHILDREN.put(GROUND_VOLUNTEER, EnumSet.noneOf(RoleType.class));
        CHILDREN.put(IT_ADMIN, EnumSet.noneOf(RoleType.class));
        CHILDREN.put(STUDENT, EnumSet.noneOf(RoleType.class));
    }

    // Roles scoped by college_id (everything except the two trust-wide roles).
    private static final Set<RoleType> COLLEGE_SCOPED = EnumSet.of(
            STUDENT, FACULTY_DEPT_COORDINATOR, HOD, GROUND_VOLUNTEER, TNP_COORDINATOR, TNP_COLLEGE_ADMIN);

    // Roles that ALSO require dept_id on top of college_id.
    private static final Set<RoleType> DEPT_SCOPED = EnumSet.of(STUDENT, FACULTY_DEPT_COORDINATOR, HOD);

    public boolean canCreate(RoleType actor, RoleType target) {
        return CAN_CREATE.getOrDefault(actor, Set.of()).contains(target);
    }

    public boolean canDeactivate(RoleType actor, RoleType target) {
        return CAN_DEACTIVATE.getOrDefault(actor, Set.of()).contains(target);
    }

    public Set<RoleType> childrenOf(RoleType role) {
        return CHILDREN.getOrDefault(role, Set.of());
    }

    public boolean isCollegeScoped(RoleType role) {
        return COLLEGE_SCOPED.contains(role);
    }

    public boolean isDeptScoped(RoleType role) {
        return DEPT_SCOPED.contains(role);
    }

    public boolean isTrustWide(RoleType role) {
        return !isCollegeScoped(role);
    }
}
