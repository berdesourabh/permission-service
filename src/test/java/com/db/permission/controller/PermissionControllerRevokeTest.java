package com.db.permission.controller;

import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsInAnyOrder;
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
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.Privilege;
import com.db.permission.exception.ErrorCode;
import com.db.permission.exception.PermissionException;
import com.db.permission.service.PermissionService;

@WebMvcTest(PermissionController.class)
class PermissionControllerRevokeTest {

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
    void revokeReturnsOkWithRevokedPrivileges() throws Exception {
        when(permissionService.revokePermission(any())).thenReturn(EnumSet.of(Privilege.SELECT, Privilege.INSERT));

        revoke(VALID_REQUEST)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Permissions revoked successfully"))
                .andExpect(jsonPath("$.username").value("sourabh"))
                .andExpect(jsonPath("$.database").value("shop"))
                .andExpect(jsonPath("$.table").value("orders"))
                .andExpect(jsonPath("$.permissions[0]").value("SELECT"))
                .andExpect(jsonPath("$.permissions[1]").value("INSERT"));

        verify(permissionService).revokePermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("SELECT", "INSERT")));
    }

    @Test
    void revokeResponseListsPrivilegesReturnedByService() throws Exception {
        when(permissionService.revokePermission(any())).thenReturn(EnumSet.of(Privilege.ALL));

        revoke(body("sourabh", "shop", "orders", "[\"select\", \"ALL\"]"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions.length()").value(1))
                .andExpect(jsonPath("$.permissions[0]").value("ALL"));
    }

    @Test
    void revokeAcceptsCreateDropAndAlter() throws Exception {
        when(permissionService.revokePermission(any())).thenReturn(EnumSet.of(Privilege.CREATE, Privilege.DROP, Privilege.ALTER));

        revoke(body("sourabh", "shop", "orders", "[\"create\", \"DROP\", \"Alter\"]"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions[*]").value(containsInAnyOrder("CREATE", "DROP", "ALTER")));

        verify(permissionService).revokePermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("create", "DROP", "Alter")));
    }

    @Test
    void revokeWithMissingFieldsReturnsValidationFailed() throws Exception {
        revoke("{}")
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.errors[*].field")
                        .value(containsInAnyOrder("username", "database", "table", "permissions")));

        verifyNoInteractions(permissionService);
    }

    static Stream<Arguments> invalidFields() {
        return Stream.of(
                Arguments.of("username injection", body("sourabh'@'%' #", "shop", "orders", "[\"SELECT\"]"), "username"),
                Arguments.of("table injection", body("sourabh", "shop", "orders FROM 'dinesh'@'%' #", "[\"SELECT\"]"), "table"),
                Arguments.of("database wildcard", body("sourabh", "*", "orders", "[\"SELECT\"]"), "database"),
                Arguments.of("unsupported privilege", body("sourabh", "shop", "orders", "[\"EXECUTE\"]"), "permissions[0]"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidFields")
    void revokeRejectsInvalidFieldBeforeCallingService(String label, String body, String field) throws Exception {
        revoke(body)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.errors.length()").value(1))
                .andExpect(jsonPath("$.errors[0].field").value(field));

        verifyNoInteractions(permissionService);
    }

    @Test
    void revokeWithMalformedJsonReturnsMalformedRequest() throws Exception {
        revoke("{not json")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("MALFORMED_REQUEST"));

        verifyNoInteractions(permissionService);
    }

    static Stream<Arguments> serviceErrors() {
        return Stream.of(
                Arguments.of(ErrorCode.GRANT_NOT_FOUND, 404,
                        "sourabh has no privileges on orders to revoke, or the account does not exist."),
                Arguments.of(ErrorCode.PROTECTED_ACCOUNT, 403,
                        "User 'root' is protected and cannot be changed through this service."),
                Arguments.of(ErrorCode.SCHEMA_NOT_ALLOWED, 403,
                        "Database 'mysql' is a restricted schema and cannot be managed through this service."),
                Arguments.of(ErrorCode.INVALID_ARGUMENTS, 400,
                        "Invalid arguments provided. Please check the request parameters and try again."),
                Arguments.of(ErrorCode.DATABASE_UNAVAILABLE, 503,
                        "The database could not be reached or did not respond in time."));
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @MethodSource("serviceErrors")
    void revokeReturnsProblemResponseWhenServiceThrows(ErrorCode code, int expectedStatus, String detail)
            throws Exception {
        doThrow(new PermissionException(code, detail)).when(permissionService).revokePermission(any());

        revoke(VALID_REQUEST)
                .andExpect(status().is(expectedStatus))
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errorCode").value(code.name()))
                .andExpect(jsonPath("$.detail").value(detail))
                .andExpect(jsonPath("$.action").value(code.getAction()));
    }

    private ResultActions revoke(String body) throws Exception {
        return mockMvc.perform(post("/permissions/revoke")
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
