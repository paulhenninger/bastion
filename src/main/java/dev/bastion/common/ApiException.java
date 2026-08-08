package dev.bastion.common;

import org.springframework.http.HttpStatus;

/** An expected, user-visible failure: carries the HTTP status and a safe message. */
public class ApiException extends RuntimeException {

    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
