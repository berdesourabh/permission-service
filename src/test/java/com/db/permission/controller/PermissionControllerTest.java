package com.db.permission.controller;

import java.sql.SQLInvalidAuthorizationSpecException;
import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTransientConnectionException;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.Privilege;
import com.db.permission.exception.DatabaseExceptionMapper;
import com.db.permission.exception.ErrorCode;
import com.db.permission.exception.PermissionException;
import com.db.permission.service.PermissionService;

@WebMvcTest(PermissionController.class)
class PermissionControllerTest {

    private static final String VALID_REQUEST = """
            {
              "username": "sourabh",
              "database": "shop",
              "table": "orders",
              "permissions": ["SELECT", "INSERT"]
            }
            """;

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private PermissionService permissionService;

    @Test
    void grantReturnsOkWithGrantedPermissions() throws Exception {
        when(permissionService.grantPermission(any())).thenReturn(EnumSet.of(Privilege.SELECT, Privilege.INSERT));

        grant(VALID_REQUEST)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Permissions granted successfully"))
                .andExpect(jsonPath("$.username").value("sourabh"))
                .andExpect(jsonPath("$.database").value("shop"))
                .andExpect(jsonPath("$.table").value("orders"))
                .andExpect(jsonPath("$.permissions[0]").value("SELECT"))
                .andExpect(jsonPath("$.permissions[1]").value("INSERT"));

        verify(permissionService).grantPermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("SELECT", "INSERT")));
    }

    @Test
    void grantAcceptsPermissionsCaseInsensitively() throws Exception {
        when(permissionService.grantPermission(any())).thenReturn(EnumSet.of(Privilege.SELECT, Privilege.INSERT));

        grant(body("sourabh", "shop", "orders", "[\"select\", \"Insert\"]"))
                .andExpect(status().isOk());

        verify(permissionService).grantPermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("select", "Insert")));
    }

    @Test
    void grantAcceptsAllPermission() throws Exception {
        when(permissionService.grantPermission(any())).thenReturn(EnumSet.of(Privilege.ALL));

        grant(body("sourabh", "shop", "orders", "[\"ALL\"]"))
                .andExpect(status().isOk());

        verify(permissionService).grantPermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("ALL")));
    }

    @Test
    void grantResponseListsPrivilegesReturnedByService() throws Exception {
        when(permissionService.grantPermission(any())).thenReturn(EnumSet.of(Privilege.SELECT));

        grant(body("sourabh", "shop", "orders", "[\"select\", \"SELECT\"]"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions.length()").value(1))
                .andExpect(jsonPath("$.permissions[0]").value("SELECT"));
    }

    @Test
    void grantAcceptsCreateDropAndAlter() throws Exception {
        when(permissionService.grantPermission(any())).thenReturn(EnumSet.of(Privilege.CREATE, Privilege.DROP, Privilege.ALTER));

        grant(body("sourabh", "shop", "orders", "[\"create\", \"DROP\", \"Alter\"]"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions[*]").value(containsInAnyOrder("CREATE", "DROP", "ALTER")));

        verify(permissionService).grantPermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("create", "DROP", "Alter")));
    }

    @Test
    void grantAcceptsHyphenAndDollarInNames() throws Exception {
        when(permissionService.grantPermission(any())).thenReturn(EnumSet.of(Privilege.SELECT));

        grant(body("sourabh.dev", "my-db", "orders$2026", "[\"SELECT\"]"))
                .andExpect(status().isOk());

        verify(permissionService).grantPermission(
                new PermissionChangeRequest("sourabh.dev", "my-db", "orders$2026", List.of("SELECT")));
    }

    @Test
    void grantWithMissingFieldsReturnsValidationFailed() throws Exception {
        grant("{}")
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.detail").value("One or more fields are invalid."))
                .andExpect(jsonPath("$.action").value(ErrorCode.VALIDATION_FAILED.getAction()))
                .andExpect(jsonPath("$.errors[*].field")
                        .value(containsInAnyOrder("username", "database", "table", "permissions")));

        verifyNoInteractions(permissionService);
    }

    @Test
    void grantWithUnsupportedPermissionReturnsValidationFailed() throws Exception {
        grant(body("sourabh", "shop", "orders", "[\"SELECT\", \"EXECUTE\"]"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.errors.length()").value(1))
                .andExpect(jsonPath("$.errors[0].field").value("permissions[1]"))
                .andExpect(jsonPath("$.errors[0].message")
                        .value("must be one of: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, ALL"));

        verifyNoInteractions(permissionService);
    }

    static Stream<Arguments> invalidFields() {
        return Stream.of(
                Arguments.of("username injection", body("sourabh'@'%' WITH GRANT OPTION #", "shop", "orders", "[\"SELECT\"]"),
                        "username", "must be a valid username"),
                Arguments.of("table injection", body("sourabh", "shop", "orders TO 'dinesh'@'%' #", "[\"SELECT\"]"),
                        "table", "must be a valid table name"),
                Arguments.of("database wildcard", body("sourabh", "*", "orders", "[\"SELECT\"]"),
                        "database", "must be a valid database name"),
                Arguments.of("table wildcard", body("sourabh", "shop", "*", "[\"SELECT\"]"),
                        "table", "must be a valid table name"),
                Arguments.of("blank username", body("", "shop", "orders", "[\"SELECT\"]"),
                        "username", "must be a valid username"),
                Arguments.of("blank database", body("sourabh", "", "orders", "[\"SELECT\"]"),
                        "database", "must be a valid database name"),
                Arguments.of("whitespace table", body("sourabh", "shop", "  ", "[\"SELECT\"]"),
                        "table", "must be a valid table name"),
                Arguments.of("space in table", body("sourabh", "shop", "order by", "[\"SELECT\"]"),
                        "table", "must be a valid table name"),
                Arguments.of("table over 64 chars", body("sourabh", "shop", "t".repeat(65), "[\"SELECT\"]"),
                        "table", "must be a valid table name"),
                Arguments.of("username over 80 chars", body("u".repeat(81), "shop", "orders", "[\"SELECT\"]"),
                        "username", "must be a valid username"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidFields")
    void grantRejectsInvalidFieldBeforeCallingService(String label, String body, String field, String message)
            throws Exception {
        grant(body)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.errors.length()").value(1))
                .andExpect(jsonPath("$.errors[0].field").value(field))
                .andExpect(jsonPath("$.errors[0].message").value(message));

        verifyNoInteractions(permissionService);
    }

    @Test
    void grantWithMalformedJsonReturnsMalformedRequest() throws Exception {
        grant("{not json")
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.errorCode").value("MALFORMED_REQUEST"))
                .andExpect(jsonPath("$.detail").value("Request body is missing or is not valid JSON."))
                .andExpect(jsonPath("$.action").value(ErrorCode.MALFORMED_REQUEST.getAction()));

        verifyNoInteractions(permissionService);
    }

    @Test
    void grantWithEmptyBodyReturnsMalformedRequest() throws Exception {
        grant("")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("MALFORMED_REQUEST"));

        verifyNoInteractions(permissionService);
    }

    @Test
    void grantReturnsInvalidArgumentsWhenServiceRejectsRequest() throws Exception {
        doThrow(new PermissionException(ErrorCode.INVALID_ARGUMENTS,
                "Invalid arguments provided. Please check the request parameters and try again."))
                .when(permissionService).grantPermission(any());

        grant(VALID_REQUEST)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errorCode").value("INVALID_ARGUMENTS"))
                .andExpect(jsonPath("$.detail")
                        .value("Invalid arguments provided. Please check the request parameters and try again."))
                .andExpect(jsonPath("$.action").value(ErrorCode.INVALID_ARGUMENTS.getAction()));
    }

    static Stream<Arguments> forbiddenErrors() {
        return Stream.of(
                Arguments.of(ErrorCode.PROTECTED_ACCOUNT,
                        "User 'root' is protected and cannot be changed through this service."),
                Arguments.of(ErrorCode.SCHEMA_NOT_ALLOWED,
                        "Database 'mysql' is a restricted schema and cannot be managed through this service."));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("forbiddenErrors")
    void grantReturnsForbiddenWhenServiceRejectsAccountOrSchema(ErrorCode code, String detail) throws Exception {
        doThrow(new PermissionException(code, detail)).when(permissionService).grantPermission(any());

        grant(VALID_REQUEST)
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errorCode").value(code.name()))
                .andExpect(jsonPath("$.detail").value(detail))
                .andExpect(jsonPath("$.action").value(code.getAction()));
    }

    static Stream<Arguments> databaseErrors() {
        String sql = "GRANT SELECT, INSERT ON shop.orders TO 'sourabh'";
        return Stream.of(
                Arguments.of(new PermissionDeniedDataAccessException("grant",
                        new SQLInvalidAuthorizationSpecException("no user", "28000", 1133)),
                        404, ErrorCode.USER_NOT_FOUND, "Account sourabh does not exist."),
                Arguments.of(new BadSqlGrammarException("grant", sql,
                        new SQLSyntaxErrorException("no table", "42S02", 1146)),
                        404, ErrorCode.TABLE_NOT_FOUND, "Database shop or table orders does not exist."),
                Arguments.of(new BadSqlGrammarException("revoke", sql,
                        new SQLSyntaxErrorException("no grant", "42000", 1147)),
                        404, ErrorCode.GRANT_NOT_FOUND,
                        "sourabh has no privileges on orders to revoke, or the account does not exist."),
                Arguments.of(new PermissionDeniedDataAccessException("grant",
                        new SQLSyntaxErrorException("access denied", "42000", 1142)),
                        403, ErrorCode.SERVICE_ACCOUNT_NOT_PERMITTED,
                        "The service account cannot manage privileges on orders, or the database does not exist."),
                Arguments.of(new CannotGetJdbcConnectionException("no connection",
                        new SQLTransientConnectionException("timed out")),
                        503, ErrorCode.DATABASE_UNAVAILABLE,
                        "The database could not be reached or did not respond in time."));
    }

    @ParameterizedTest(name = "{2} -> {1}")
    @MethodSource("databaseErrors")
    void grantMapsDatabaseErrorToProblemResponse(Exception dbException, int expectedStatus,
            ErrorCode expectedCode, String expectedDetail) throws Exception {
        doThrow(DatabaseExceptionMapper.map(dbException, "sourabh", "shop", "orders"))
                .when(permissionService).grantPermission(any());

        grant(VALID_REQUEST)
                .andExpect(status().is(expectedStatus))
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(expectedStatus))
                .andExpect(jsonPath("$.errorCode").value(expectedCode.name()))
                .andExpect(jsonPath("$.detail").value(expectedDetail))
                .andExpect(jsonPath("$.action").value(expectedCode.getAction()));
    }

    @Test
    void grantReturnsInternalErrorWithoutLeakingDetailsOnUnexpectedException() throws Exception {
        doThrow(new IllegalStateException("connection refused to db-host:3306"))
                .when(permissionService).grantPermission(any());

        grant(VALID_REQUEST)
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.errorCode").value("INTERNAL_ERROR"))
                .andExpect(jsonPath("$.detail").value("An unexpected error occurred."))
                .andExpect(jsonPath("$.action").value(ErrorCode.INTERNAL_ERROR.getAction()))
                .andExpect(content().string(not(containsString("db-host"))));
    }

    private ResultActions grant(String body) throws Exception {
        return mockMvc.perform(post("/permissions/grant")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private static String body(String username, String database, String table, String permissions) {
        return "{\"username\": \"" + username + "\","
                + " \"database\": \"" + database + "\","
                + " \"table\": \"" + table + "\","
                + " \"permissions\": " + permissions + "}";
    }
}
