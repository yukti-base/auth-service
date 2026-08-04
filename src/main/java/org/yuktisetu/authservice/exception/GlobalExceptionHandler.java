package org.yuktisetu.authservice.exception;

import org.yuktisetu.authservice.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthExceptions.InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentials(AuthExceptions.InvalidCredentialsException ex) {
        // Deliberately identical response/status whether the email doesn't exist
        // or the password is wrong — do not let this endpoint be used to enumerate
        // valid emails.
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ErrorResponse.of("INVALID_CREDENTIALS", ex.getMessage()));
    }

    @ExceptionHandler(AuthExceptions.AccountLockedException.class)
    public ResponseEntity<ErrorResponse> handleLocked(AuthExceptions.AccountLockedException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(ErrorResponse.of("ACCOUNT_LOCKED", ex.getMessage()));
    }

    @ExceptionHandler(AuthExceptions.AccountInactiveException.class)
    public ResponseEntity<ErrorResponse> handleInactive(AuthExceptions.AccountInactiveException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of("ACCOUNT_INACTIVE", ex.getMessage()));
    }

    @ExceptionHandler(AuthExceptions.InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRefresh(AuthExceptions.InvalidRefreshTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ErrorResponse.of("INVALID_REFRESH_TOKEN", ex.getMessage()));
    }

    @ExceptionHandler(AuthExceptions.NoActiveRoleException.class)
    public ResponseEntity<ErrorResponse> handleNoRole(AuthExceptions.NoActiveRoleException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of("NO_ACTIVE_ROLE", ex.getMessage()));
    }

    @ExceptionHandler(AuthExceptions.UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUserAlreadyExists(AuthExceptions.UserAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ErrorResponse.of("USER_ALREADY_EXISTS", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponse.of("VALIDATION_ERROR", "Request payload failed validation"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex) {
        // Never return ex.getMessage() here for unknown exceptions — that's how
        // stack traces / SQL fragments leak to clients. Log it server-side instead.
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of("INTERNAL_ERROR", "Something went wrong"));
    }
}
