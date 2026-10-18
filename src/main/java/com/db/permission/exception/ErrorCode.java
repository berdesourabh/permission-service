package com.db.permission.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {

    VALIDATION_FAILED(HttpStatus.BAD_REQUEST,
            "Fix the fields listed in 'errors' and try again."),
    MALFORMED_REQUEST(HttpStatus.BAD_REQUEST,
            "Send a JSON body with username, database, table and permissions."),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR,
            "Unexpected error. Check the service logs around the time of the request.");

    private final HttpStatus status;
    private final String action;

    private ErrorCode(HttpStatus status, String action) {
        this.status = status;
        this.action = action;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getAction() {
        return action;
    }

}
