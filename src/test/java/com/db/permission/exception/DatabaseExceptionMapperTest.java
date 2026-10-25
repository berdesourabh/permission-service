package com.db.permission.exception;

import java.net.ConnectException;
import java.sql.SQLException;
import java.sql.SQLInvalidAuthorizationSpecException;
import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTransientConnectionException;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.UncategorizedSQLException;

class DatabaseExceptionMapperTest {

    private static final String SQL = "GRANT SELECT ON shop.orders TO 'sourabh'";
    private static final String UNAVAILABLE = "The database could not be reached or did not respond in time.";

    static Stream<Arguments> mappings() {
        return Stream.of(
                Arguments.of("1133 unknown user", new PermissionDeniedDataAccessException("grant",
                        new SQLInvalidAuthorizationSpecException("Can't find any matching row in the user table", "28000", 1133)),
                        ErrorCode.USER_NOT_FOUND, "Account sourabh does not exist."),
                Arguments.of("1146 missing table", new BadSqlGrammarException("grant", SQL,
                        new SQLSyntaxErrorException("Table 'shop.orders' doesn't exist", "42S02", 1146)),
                        ErrorCode.TABLE_NOT_FOUND, "Database shop or table orders does not exist."),
                Arguments.of("1141 no grant for user", new BadSqlGrammarException("revoke", SQL,
                        new SQLSyntaxErrorException("There is no such grant defined", "42000", 1141)),
                        ErrorCode.GRANT_NOT_FOUND, "sourabh has no privileges on orders to revoke, or the account does not exist."),
                Arguments.of("1147 no grant on table", new BadSqlGrammarException("revoke", SQL,
                        new SQLSyntaxErrorException("There is no such grant defined", "42000", 1147)),
                        ErrorCode.GRANT_NOT_FOUND, "sourabh has no privileges on orders to revoke, or the account does not exist."),
                Arguments.of("1044 access denied to database", new PermissionDeniedDataAccessException("grant",
                        new SQLSyntaxErrorException("Access denied for user 'perm_svc'@'%'", "42000", 1044)),
                        ErrorCode.SERVICE_ACCOUNT_NOT_PERMITTED, "The service account cannot manage privileges on orders, or the database does not exist."),
                Arguments.of("1142 access denied to table", new PermissionDeniedDataAccessException("grant",
                        new SQLSyntaxErrorException("Access denied for user 'perm_svc'@'%'", "42000", 1142)),
                        ErrorCode.SERVICE_ACCOUNT_NOT_PERMITTED, "The service account cannot manage privileges on orders, or the database does not exist."),
                Arguments.of("connection failure", new CannotGetJdbcConnectionException("Failed to obtain JDBC Connection",
                        new SQLTransientConnectionException("Connection is not available, request timed out after 30000ms")),
                        ErrorCode.DATABASE_UNAVAILABLE, UNAVAILABLE),
                Arguments.of("connection failure without SQL cause", connectionRefused(),
                        ErrorCode.DATABASE_UNAVAILABLE, UNAVAILABLE),
                Arguments.of("query timeout", new QueryTimeoutException("Query timed out",
                        new SQLException("Query execution was interrupted", "70100", 1317)),
                        ErrorCode.DATABASE_UNAVAILABLE, UNAVAILABLE),
                Arguments.of("unknown database error", new UncategorizedSQLException("grant", SQL,
                        new SQLException("Something unusual", "HY000", 9999)),
                        ErrorCode.INTERNAL_ERROR, "Unexpected database error."),
                Arguments.of("non-database exception", new IllegalStateException("boom"),
                        ErrorCode.INTERNAL_ERROR, "Unexpected database error."));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("mappings")
    void mapsToErrorCodeAndMessage(String label, Exception exception, ErrorCode expectedCode, String expectedMessage) {
        PermissionException result = DatabaseExceptionMapper.map(exception, "sourabh", "shop", "orders");

        assertThat(result.getErrorCode()).isEqualTo(expectedCode);
        assertThat(result.getMessage()).isEqualTo(expectedMessage);
    }

    @Test
    void doesNotExposeRawDatabaseMessage() {
        Exception e = new BadSqlGrammarException("grant", SQL,
                new SQLSyntaxErrorException("Table 'internal_db.secret_table' doesn't exist", "42S02", 1146));

        assertThat(DatabaseExceptionMapper.map(e, "sourabh", "shop", "orders").getMessage())
                .doesNotContain("internal_db", "secret_table");
    }

    private static Exception connectionRefused() {
        Exception e = new CannotGetJdbcConnectionException("Failed to obtain JDBC Connection");
        e.initCause(new ConnectException("Connection refused"));
        return e;
    }
}
