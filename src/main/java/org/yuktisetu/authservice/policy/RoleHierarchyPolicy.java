package org.yuktisetu.authservice.policy;

import org.springframework.stereotype.Component;
import org.yuktisetu.model.RoleHierarchy;
import org.yuktisetu.model.RoleType;

import java.util.Set;

/**
 * Thin wrapper around the shared RoleHierarchy in user-dal, kept as a
 * @Component so it stays injectable exactly as before -- no call-site
 * changes needed in RoleManagementService. The actual rule tables now live
 * in one place (RoleHierarchy) so auth-service's role-management authority
 * and user-service's profile-visibility rule can never drift apart.
 */
@Component
public class RoleHierarchyPolicy {

    public boolean canCreate(RoleType actor, RoleType target) {
        return RoleHierarchy.canCreate(actor, target);
    }

    public boolean canDeactivate(RoleType actor, RoleType target) {
        return RoleHierarchy.canDeactivate(actor, target);
    }

    public Set<RoleType> childrenOf(RoleType role) {
        return RoleHierarchy.childrenOf(role);
    }

    public boolean isCollegeScoped(RoleType role) {
        return RoleHierarchy.isCollegeScoped(role);
    }

    public boolean isDeptScoped(RoleType role) {
        return RoleHierarchy.isDeptScoped(role);
    }

    public boolean isTrustWide(RoleType role) {
        return RoleHierarchy.isTrustWide(role);
    }

    public int authorityRank(RoleType role) {
        return RoleHierarchy.authorityRank(role);
    }
}
