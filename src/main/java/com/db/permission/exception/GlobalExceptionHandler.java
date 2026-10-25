package com.db.permission.exception;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.method.ParameterValidationResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.db.permission.dto.FieldErrorItem;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(PermissionException.class)
    public ResponseEntity<ProblemDetail> handlePermissionException(PermissionException exception) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(exception.getErrorCode().getStatus());
        return response.body(problem(exception.getErrorCode(), exception.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(Exception e) {
        log.error("Unexpected error", e);
        return ResponseEntity.internalServerError()
                .body(problem(ErrorCode.INTERNAL_ERROR, "An unexpected error occurred."));
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<FieldErrorItem> errors = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> new FieldErrorItem(fe.getField(), fe.getDefaultMessage()))
                .toList();
        return validationFailed(errors);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.info("Malformed request body: {}", ex.getMessage());
        return ResponseEntity.status(ErrorCode.MALFORMED_REQUEST.getStatus())
                .body(problem(ErrorCode.MALFORMED_REQUEST, "Request body is missing or is not valid JSON."));
    }

    @Override
    protected ResponseEntity<Object> handleHandlerMethodValidationException(HandlerMethodValidationException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<FieldErrorItem> errors = new ArrayList<>();
        for (ParameterValidationResult result : ex.getParameterValidationResults()) {
            String name = result.getMethodParameter().getParameterName();
            result.getResolvableErrors().forEach(err -> errors.add(new FieldErrorItem(name, err.getDefaultMessage())));
        }
        return validationFailed(errors);
    }

    private ResponseEntity<Object> validationFailed(List<FieldErrorItem> errors) {
        log.info("Validation failed: {}", errors);
        ProblemDetail body = problem(ErrorCode.VALIDATION_FAILED, "One or more fields are invalid.");
        body.setProperty("errors", errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    private static ProblemDetail problem(ErrorCode code, String detail) {
        ProblemDetail body = ProblemDetail.forStatusAndDetail(code.getStatus(), detail);
        body.setProperty("errorCode", code.name());
        body.setProperty("action", code.getAction());
        return body;
    }

}
