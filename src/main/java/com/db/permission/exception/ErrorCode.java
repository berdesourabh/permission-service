package com.db.permission.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {

    VALIDATION_FAILED(HttpStatus.BAD_REQUEST,
            "Fix the fields listed in 'errors' and try again."),
    MALFORMED_REQUEST(HttpStatus.BAD_REQUEST,
            "Send a JSON body with username, database, table and permissions."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND,
            "Check the username and host. The user may exist under a different host."),
    TABLE_NOT_FOUND(HttpStatus.NOT_FOUND,
            "Check the database and table names (they are case-sensitive)."),
    GRANT_NOT_FOUND(HttpStatus.NOT_FOUND,
            "The user may not have any privileges on the table, or the user may not exist."),
    SERVICE_ACCOUNT_NOT_PERMITTED(HttpStatus.FORBIDDEN,
            "The service account cannot manage privileges on the table, or the database does not exist."),
    DATABASE_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE,
            "The database could not be reached or did not respond in time."),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR,
            "Unexpected error. Check the service logs around the time of the request."),
    INVALID_ARGUMENTS(HttpStatus.BAD_REQUEST,
            "Invalid arguments provided. Please check the request parameters and try again."),
    PROTECTED_ACCOUNT(HttpStatus.FORBIDDEN,
            "This account cannot be changed through the service. Ask a DBA."),
    SCHEMA_NOT_ALLOWED(HttpStatus.FORBIDDEN,
            "This schema cannot be managed through the service. Ask a DBA.");

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
