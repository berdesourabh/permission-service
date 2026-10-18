package com.db.permission.exception;

import java.sql.SQLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.TransientDataAccessException;

public class DatabaseExceptionMapper {

    private static final Logger log = LoggerFactory.getLogger(DatabaseExceptionMapper.class);

    public static PermissionException map(Exception e, String account, String table) {
        int dbErrorCode = e.getCause() instanceof SQLException sql ? sql.getErrorCode() : 0;

        log.warn("Database error {} for {} on {}: {}", dbErrorCode, account, table, e.getMessage());

        return switch (dbErrorCode) {
            case 1133 ->
                new PermissionException(ErrorCode.USER_NOT_FOUND,
                "Account " + account + " does not exist.");
            case 1141, 1147 ->
                new PermissionException(ErrorCode.GRANT_NOT_FOUND,
                account + " has no privileges on " + table + " to revoke, or the account does not exist.");
            case 1146 ->
                new PermissionException(ErrorCode.TABLE_NOT_FOUND,
                "Table " + table + " does not exist.");
            case 1044, 1142 ->
                new PermissionException(ErrorCode.SERVICE_ACCOUNT_NOT_PERMITTED,
                "The service account cannot manage privileges on " + table + ", or the database does not exist.");
            default -> {
                if (e instanceof DataAccessResourceFailureException || e instanceof TransientDataAccessException) {
                    yield new PermissionException(ErrorCode.DATABASE_UNAVAILABLE,
                    "The database could not be reached or did not respond in time.");
                }
                yield new PermissionException(ErrorCode.INTERNAL_ERROR, "Unexpected database error.");
            }
        };
    }
}
