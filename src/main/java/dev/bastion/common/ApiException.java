package dev.bastion.common;

import org.springframework.http.HttpStatus;

/**
 * An expected, user-visible failure: carries the HTTP status, a safe message and,
 * where the SPA needs to react to it, a stable machine-readable code.
 */
public class ApiException extends RuntimeException {

    /** Codes the client branches on. Messages may change; these may not. */
    public static final String EMAIL_NOT_VERIFIED = "EMAIL_NOT_VERIFIED";
    public static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
    public static final String REAUTH_REQUIRED = "REAUTH_REQUIRED";
    public static final String ADMIN_MFA_REQUIRED = "ADMIN_MFA_REQUIRED";
    public static final String SIGNUPS_CLOSED = "SIGNUPS_CLOSED";
    public static final String BREACHED_PASSWORD = "BREACHED_PASSWORD";
    public static final String RATE_LIMITED = "RATE_LIMITED";

    private final HttpStatus status;
    private final String code;

    public ApiException(HttpStatus status, String message) {
        this(status, message, null);
    }

    public ApiException(HttpStatus status, String message, String code) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    public static ApiException badRequest(String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, message);
    }

    public static ApiException notFound(String message) {
        return new ApiException(HttpStatus.NOT_FOUND, message);
    }

    public static ApiException tooManyRequests(String message) {
        return new ApiException(HttpStatus.TOO_MANY_REQUESTS, message, RATE_LIMITED);
    }
}
