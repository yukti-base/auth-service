package org.yuktisetu.authservice.exception;

import io.jsonwebtoken.ExpiredJwtException;

public final class AuthExceptions {

    private AuthExceptions() {}

    public static class InvalidCredentialsException extends RuntimeException {
        public InvalidCredentialsException() {
            super("Invalid email or password");
        }
    }

    public static class AccountLockedException extends RuntimeException {
        public AccountLockedException(long retryAfterSeconds) {
            super("Account temporarily locked. Retry after " + retryAfterSeconds + "s");
        }
    }

    public static class AccountInactiveException extends RuntimeException {
        public AccountInactiveException() {
            super("Account is inactive or deleted");
        }
    }

    public static class InvalidRefreshTokenException extends RuntimeException {
        public InvalidRefreshTokenException() {
            super("Refresh token is invalid, expired, or already used");
        }
    }

    public static class NoActiveRoleException extends RuntimeException {
        public NoActiveRoleException() {
            super("Account has no active role assignment");
        }
    }

    public static class UserAlreadyExistsException extends RuntimeException {
        public UserAlreadyExistsException() {
            super("User already exists");
        }
    }

    public static class InsufficientAuthorityException extends RuntimeException {
        public InsufficientAuthorityException() {
            super("Actor role is not permitted to perform this action on the target role.");
        }
    }

    public static class ScopeViolationException extends RuntimeException {
        public ScopeViolationException() {
            super("Target college/department is outside the actor's assigned scope.");
        }
    }

    public static class LastActiveHolderException extends RuntimeException {
        public LastActiveHolderException() {
            super("Cannot deactivate the last active holder of this role while active subordinates exist in scope. Add a replacement first.");
        }
    }

    public static class NotYetDeactivatedException extends RuntimeException {
        public NotYetDeactivatedException() {
            super("Target must be deactivated before it can be hard-deleted.");
        }
    }

    public static class InvalidInviteException extends RuntimeException {
        public InvalidInviteException() {
            super("Invite token is invalid, expired, or already used.");
        }
    }

    public static class TokenExpiredException extends RuntimeException {
        public TokenExpiredException(ExpiredJwtException e) {
            super("Token has expired.", e);
        }
    }

    public static class InvalidTokenException extends RuntimeException {
        public InvalidTokenException(Throwable cause) {
            super("Token is invalid.", cause);
        }
    }

    public static class InvalidRegistrationRoleException extends RuntimeException {
        public InvalidRegistrationRoleException() {
            super("Public registration is only permitted for IT_ADMIN or TNP_SUPER_ADMIN roles");
        }
    }
}