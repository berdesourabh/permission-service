package com.db.permission.exception;

import java.net.ConnectException;
import java.sql.SQLException;
import java.sql.SQLInvalidAuthorizationSpecException;
import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTransientConnectionException;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.UncategorizedSQLException;

class DatabaseExceptionMapperTest {

    private static final String ACCOUNT = "sourabh";
    private static final String DATABASE = "shop";
    private static final String TABLE = "orders";
    private static final String SQL = "GRANT SELECT ON shop.orders TO 'sourabh'";

    @Test
    void missingUserMapsToUserNotFound() {
        Exception e = new PermissionDeniedDataAccessException("grant",
                new SQLInvalidAuthorizationSpecException("Can't find any matching row in the user table", "28000", 1133));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_FOUND);
        assertThat(result.getMessage()).isEqualTo("Account sourabh does not exist.");
    }

    @Test
    void missingTableMapsToTableNotFound() {
        Exception e = new BadSqlGrammarException("grant", SQL,
                new SQLSyntaxErrorException("Table 'shop.orders' doesn't exist", "42S02", 1146));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.TABLE_NOT_FOUND);
        assertThat(result.getMessage()).isEqualTo("Database shop or table orders does not exist.");
    }

    @ParameterizedTest
    @ValueSource(ints = {1141, 1147})
    void missingGrantMapsToGrantNotFound(int dbErrorCode) {
        Exception e = new BadSqlGrammarException("revoke", SQL,
                new SQLSyntaxErrorException("There is no such grant defined", "42000", dbErrorCode));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.GRANT_NOT_FOUND);
        assertThat(result.getMessage())
                .isEqualTo("sourabh has no privileges on orders to revoke, or the account does not exist.");
    }

    @ParameterizedTest
    @ValueSource(ints = {1044, 1142})
    void accessDeniedMapsToServiceAccountNotPermitted(int dbErrorCode) {
        Exception e = new PermissionDeniedDataAccessException("grant",
                new SQLSyntaxErrorException("Access denied for user 'perm_svc'@'%'", "42000", dbErrorCode));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.SERVICE_ACCOUNT_NOT_PERMITTED);
        assertThat(result.getMessage())
                .isEqualTo("The service account cannot manage privileges on orders, or the database does not exist.");
    }

    @Test
    void connectionFailureMapsToDatabaseUnavailable() {
        Exception e = new CannotGetJdbcConnectionException("Failed to obtain JDBC Connection",
                new SQLTransientConnectionException("Connection is not available, request timed out after 30000ms"));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.DATABASE_UNAVAILABLE);
        assertThat(result.getMessage()).isEqualTo("The database could not be reached or did not respond in time.");
    }

    @Test
    void connectionFailureWithoutSqlCauseMapsToDatabaseUnavailable() {
        Exception e = new CannotGetJdbcConnectionException("Failed to obtain JDBC Connection");
        e.initCause(new ConnectException("Connection refused"));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.DATABASE_UNAVAILABLE);
    }

    @Test
    void transientFailureMapsToDatabaseUnavailable() {
        Exception e = new QueryTimeoutException("Query timed out",
                new SQLException("Query execution was interrupted", "70100", 1317));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.DATABASE_UNAVAILABLE);
    }

    @Test
    void unknownDatabaseErrorMapsToInternalError() {
        Exception e = new UncategorizedSQLException("grant", SQL,
                new SQLException("Something unusual", "HY000", 9999));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR);
        assertThat(result.getMessage()).isEqualTo("Unexpected database error.");
    }

    @Test
    void nonDatabaseExceptionMapsToInternalError() {
        PermissionException result = DatabaseExceptionMapper.map(
                new IllegalStateException("boom"), ACCOUNT, DATABASE, TABLE);

        assertThat(result.getErrorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR);
        assertThat(result.getMessage()).isEqualTo("Unexpected database error.");
    }

    @Test
    void mappedMessageDoesNotExposeRawDatabaseMessage() {
        Exception e = new BadSqlGrammarException("grant", SQL,
                new SQLSyntaxErrorException("Table 'internal_db.secret_table' doesn't exist", "42S02", 1146));

        PermissionException result = DatabaseExceptionMapper.map(e, ACCOUNT, DATABASE, TABLE);

        assertThat(result.getMessage()).doesNotContain("internal_db", "secret_table");
    }
}
