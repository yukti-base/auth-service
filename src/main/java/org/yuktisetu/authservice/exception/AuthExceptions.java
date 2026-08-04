package org.yuktisetu.authservice.exception;

public final class AuthExceptions {

    private AuthExceptions() {}

    public static class InvalidCredentialsException extends RuntimeException {
        public InvalidCredentialsException() { super("Invalid email or password"); }
    }

    public static class AccountLockedException extends RuntimeException {
        public AccountLockedException(long retryAfterSeconds) {
            super("Account temporarily locked. Retry after " + retryAfterSeconds + "s");
        }
    }

    public static class AccountInactiveException extends RuntimeException {
        public AccountInactiveException() { super("Account is inactive or deleted"); }
    }

    public static class InvalidRefreshTokenException extends RuntimeException {
        public InvalidRefreshTokenException() { super("Refresh token is invalid, expired, or already used"); }
    }

    public static class NoActiveRoleException extends RuntimeException {
        public NoActiveRoleException() { super("Account has no active role assignment"); }
    }

    public static class UserAlreadyExistsException extends RuntimeException {
        public UserAlreadyExistsException() { super("User already exists"); }
    }
}
