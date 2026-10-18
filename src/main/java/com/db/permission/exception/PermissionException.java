package com.db.permission.exception;

public class PermissionException extends RuntimeException {

    private final ErrorCode errorCode;

    public PermissionException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
