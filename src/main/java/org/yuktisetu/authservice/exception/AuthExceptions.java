package org.yuktisetu.authservice.exception;

import org.springframework.http.HttpStatus;
import org.yuktisetu.core.exception.ApiException;
import org.yuktisetu.core.exception.ConflictException;

public final class AuthExceptions {

    private AuthExceptions() {}

    public static class InvalidCredentialsException extends ApiException {
        public InvalidCredentialsException() {
            super(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid email or password");
        }
    }

    public static class AccountLockedException extends ApiException {
        public AccountLockedException(long retryAfterSeconds) {
            super(HttpStatus.TOO_MANY_REQUESTS, "ACCOUNT_LOCKED", "Account temporarily locked. Retry after " + retryAfterSeconds + "s");
        }
    }

    public static class AccountInactiveException extends ApiException {
        public AccountInactiveException() {
            super(HttpStatus.FORBIDDEN, "ACCOUNT_INACTIVE", "Account is inactive or deleted");
        }
    }

    public static class InvalidRefreshTokenException extends ApiException {
        public InvalidRefreshTokenException() {
            super(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN", "Refresh token is invalid, expired, or already used");
        }
    }

    public static class NoActiveRoleException extends ApiException {
        public NoActiveRoleException() {
            super(HttpStatus.FORBIDDEN, "NO_ACTIVE_ROLE", "Account has no active role assignment");
        }
    }

    public static class UserAlreadyExistsException extends ConflictException {
        public UserAlreadyExistsException() {
            super("USER_ALREADY_EXISTS", "User already exists");
        }
    }

    public static class InsufficientAuthorityException extends ApiException {
        public InsufficientAuthorityException() {
            super(HttpStatus.FORBIDDEN, "INSUFFICIENT_AUTHORITY", "Actor role is not permitted to perform this action on the target role.");
        }
    }

    public static class ScopeViolationException extends ApiException {
        public ScopeViolationException() {
            super(HttpStatus.FORBIDDEN, "SCOPE_VIOLATION", "Target college/department is outside the actor's assigned scope.");
        }
    }

    public static class LastActiveHolderException extends ApiException {
        public LastActiveHolderException() {
            super(HttpStatus.FORBIDDEN, "LAST_ACTIVE_HOLDER", "Cannot deactivate the last active holder of this role while active subordinates exist in scope. Add a replacement first.");
        }
    }

    public static class NotYetDeactivatedException extends ConflictException {
        public NotYetDeactivatedException() {
            super("NOT_YET_DEACTIVATED", "Target must be deactivated before it can be deleted.");
        }
    }

    /** Hard delete only: soft-delete the account first, then remove it permanently. */
    public static class NotSoftDeletedException extends ConflictException {
        public NotSoftDeletedException() {
            super("NOT_SOFT_DELETED", "Target must be soft-deleted before it can be permanently removed.");
        }
    }

    /**
     * Hard delete only: connected child or audit records still reference this
     * user and would be destroyed by the JPA cascade. Refuse rather than cascade.
     */
    public static class CascadeBlockedException extends ConflictException {
        public CascadeBlockedException(String detail) {
            super("CASCADE_BLOCKED",
                    "Cannot permanently delete: connected records still reference this user (" + detail
                            + "). Resolve or reassign them first.");
        }
    }

    public static class InvalidInviteException extends ApiException {
        public InvalidInviteException() {
            super(HttpStatus.UNAUTHORIZED, "INVALID_INVITE", "Invite token is invalid, expired, or already used.");
        }
    }

    public static class InvalidRegistrationRoleException extends ApiException {
        public InvalidRegistrationRoleException() {
            super(HttpStatus.FORBIDDEN, "INVALID_REGISTRATION_ROLE", "Public registration is only permitted for IT_ADMIN or TNP_SUPER_ADMIN roles");
        }
    }

    public static class BadCredentialsExceptions extends ApiException {
        public BadCredentialsExceptions(String error) {
            super(HttpStatus.BAD_REQUEST, "BAD_CREDENTIALS", error);
        }
    }

    public static class PasswordMismatchException extends ApiException {
        public PasswordMismatchException() {
            super(HttpStatus.BAD_REQUEST, "PASSWORD_MISMATCH", "New password and confirm password do not match");
        }
    }
}