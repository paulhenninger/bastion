package dev.bastion.common;

import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Every error leaves as {@code {"message": "...", "code"?: "...", "fields"?: {...}}}.
 *
 * <p>Two rules this enforces. Nothing internal reaches the client — no stack trace,
 * no exception message, no class name. And a malformed request is the caller's
 * fault (4xx), never a 500: the framework's own exceptions carry their status, and
 * a catch-all that turned "body is not JSON" into a server error would page the
 * operator for every scanner on the internet.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String MESSAGE = "message";

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> apiException(ApiException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put(MESSAGE, e.getMessage());
        if (e.getCode() != null) {
            body.put("code", e.getCode());
        }
        return ResponseEntity.status(e.getStatus()).body(body);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> validation(MethodArgumentNotValidException e) {
        Map<String, String> fields = new LinkedHashMap<>();
        e.getBindingResult().getFieldErrors().forEach(f ->
                fields.putIfAbsent(f.getField(), f.getDefaultMessage()));
        return ResponseEntity.badRequest().body(Map.of(
                MESSAGE, fields.isEmpty() ? "Validation failed" : fields.values().iterator().next(),
                "fields", fields));
    }

    @ExceptionHandler({HandlerMethodValidationException.class, ConstraintViolationException.class,
            MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Map<String, Object>> invalidParameter(Exception e) {
        return ResponseEntity.badRequest().body(Map.of(MESSAGE, "Invalid request parameters"));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> unreadable(HttpMessageNotReadableException e) {
        // Also where an over-limit body lands (RequestBodyLimitFilter fails the stream).
        return ResponseEntity.badRequest().body(Map.of(MESSAGE, "Malformed or oversized request body"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception e) {
        // Spring's own exceptions (405, 415, 404 for unknown paths, missing params…)
        // already know their status; answer with it and a generic reason.
        if (e instanceof ErrorResponse errorResponse) {
            HttpStatusCode status = errorResponse.getStatusCode();
            if (status.is4xxClientError()) {
                HttpStatus resolved = HttpStatus.resolve(status.value());
                String reason = resolved == null ? "Request rejected" : resolved.getReasonPhrase();
                return ResponseEntity.status(status).body(Map.of(MESSAGE, reason));
            }
        }
        // Never leak internals to the client; the log line has the detail.
        log.error("Unhandled exception", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(MESSAGE, "Something went wrong"));
    }
}
