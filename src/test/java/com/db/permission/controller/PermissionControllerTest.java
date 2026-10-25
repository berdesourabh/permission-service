package com.db.permission.controller;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.Privilege;
import com.db.permission.dto.TableGrant;
import com.db.permission.exception.ErrorCode;
import com.db.permission.exception.PermissionException;
import com.db.permission.service.PermissionService;

@WebMvcTest(PermissionController.class)
class PermissionControllerTest {

    private static final String VALID_REQUEST = body("sourabh", "shop", "orders", "[\"SELECT\", \"INSERT\"]");

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private PermissionService permissionService;

    enum Endpoint {
        GRANT("/permissions/grant", "Permissions granted successfully"),
        REVOKE("/permissions/revoke", "Permissions revoked successfully");

        private final String path;
        private final String message;

        Endpoint(String path, String message) {
            this.path = path;
            this.message = message;
        }

        // Works for when(...), verify(...) and doThrow(...).when(...) alike.
        EnumSet<Privilege> invoke(PermissionService service, PermissionChangeRequest request) {
            return this == GRANT ? service.grantPermission(request) : service.revokePermission(request);
        }
    }

    @Nested
    class GrantAndRevoke {

        @ParameterizedTest
        @EnumSource(Endpoint.class)
        void returnsPrivilegesFromService(Endpoint endpoint) throws Exception {
            when(endpoint.invoke(permissionService, any())).thenReturn(EnumSet.of(Privilege.SELECT, Privilege.INSERT));

            send(endpoint, VALID_REQUEST)
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value(endpoint.message))
                    .andExpect(jsonPath("$.username").value("sourabh"))
                    .andExpect(jsonPath("$.database").value("shop"))
                    .andExpect(jsonPath("$.table").value("orders"))
                    .andExpect(jsonPath("$.permissions[0]").value("SELECT"))
                    .andExpect(jsonPath("$.permissions[1]").value("INSERT"));

            endpoint.invoke(verify(permissionService),
                    new PermissionChangeRequest("sourabh", "shop", "orders", List.of("SELECT", "INSERT")));
        }

        @ParameterizedTest
        @EnumSource(Endpoint.class)
        void responseListsPrivilegesReturnedByServiceNotRequested(Endpoint endpoint) throws Exception {
            when(endpoint.invoke(permissionService, any())).thenReturn(EnumSet.of(Privilege.ALL));

            send(endpoint, body("sourabh", "shop", "orders", "[\"select\", \"ALL\"]"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.permissions.length()").value(1))
                    .andExpect(jsonPath("$.permissions[0]").value("ALL"));
        }

        @ParameterizedTest(name = "{0} {1}")
        @MethodSource("com.db.permission.controller.PermissionControllerTest#validRequests")
        void acceptsValidRequest(Endpoint endpoint, String label, PermissionChangeRequest request) throws Exception {
            when(endpoint.invoke(permissionService, any())).thenReturn(EnumSet.of(Privilege.SELECT));

            send(endpoint, body(request)).andExpect(status().isOk());

            endpoint.invoke(verify(permissionService), request);
        }

        @ParameterizedTest
        @EnumSource(Endpoint.class)
        void rejectsMissingFields(Endpoint endpoint) throws Exception {
            send(endpoint, "{}")
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

        @ParameterizedTest(name = "{0} {1}")
        @MethodSource("com.db.permission.controller.PermissionControllerTest#invalidFields")
        void rejectsInvalidField(Endpoint endpoint, String label, String body, String field, String message)
                throws Exception {
            send(endpoint, body)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorCode").value("VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.errors.length()").value(1))
                    .andExpect(jsonPath("$.errors[0].field").value(field))
                    .andExpect(jsonPath("$.errors[0].message").value(message));

            verifyNoInteractions(permissionService);
        }

        @ParameterizedTest(name = "{0} body \"{1}\"")
        @MethodSource("com.db.permission.controller.PermissionControllerTest#unreadableBodies")
        void rejectsUnreadableBody(Endpoint endpoint, String body) throws Exception {
            send(endpoint, body)
                    .andExpect(status().isBadRequest())
                    .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                    .andExpect(jsonPath("$.errorCode").value("MALFORMED_REQUEST"))
                    .andExpect(jsonPath("$.detail").value("Request body is missing or is not valid JSON."))
                    .andExpect(jsonPath("$.action").value(ErrorCode.MALFORMED_REQUEST.getAction()));

            verifyNoInteractions(permissionService);
        }

        @ParameterizedTest(name = "{0} {1}")
        @MethodSource("com.db.permission.controller.PermissionControllerTest#serviceErrors")
        void returnsProblemResponseForServiceError(Endpoint endpoint, ErrorCode code) throws Exception {
            endpoint.invoke(doThrow(new PermissionException(code, "detail for " + code)).when(permissionService), any());

            send(endpoint, VALID_REQUEST)
                    .andExpect(status().is(code.getStatus().value()))
                    .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                    .andExpect(jsonPath("$.status").value(code.getStatus().value()))
                    .andExpect(jsonPath("$.errorCode").value(code.name()))
                    .andExpect(jsonPath("$.detail").value("detail for " + code))
                    .andExpect(jsonPath("$.action").value(code.getAction()));
        }

        @ParameterizedTest
        @EnumSource(Endpoint.class)
        void returnsInternalErrorWithoutLeakingDetails(Endpoint endpoint) throws Exception {
            endpoint.invoke(doThrow(new IllegalStateException("connection refused to db-host:3306")).when(permissionService), any());

            send(endpoint, VALID_REQUEST)
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.errorCode").value("INTERNAL_ERROR"))
                    .andExpect(jsonPath("$.detail").value("An unexpected error occurred."))
                    .andExpect(jsonPath("$.action").value(ErrorCode.INTERNAL_ERROR.getAction()))
                    .andExpect(content().string(not(containsString("db-host"))));
        }
    }

    @Nested
    class GetPermissions {

        @Test
        void returnsGrantsForUser() throws Exception {
            when(permissionService.getPermissionsForUser("sourabh")).thenReturn(List.of(
                    new TableGrant("%", "shop", "customers", List.of("UPDATE")),
                    new TableGrant("localhost", "shop", "orders", List.of("SELECT", "INSERT"))));

            mockMvc.perform(get("/permissions/sourabh"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value("sourabh"))
                    .andExpect(jsonPath("$.grants.length()").value(2))
                    .andExpect(jsonPath("$.grants[0].host").value("%"))
                    .andExpect(jsonPath("$.grants[0].database").value("shop"))
                    .andExpect(jsonPath("$.grants[0].table").value("customers"))
                    .andExpect(jsonPath("$.grants[0].privileges[0]").value("UPDATE"))
                    .andExpect(jsonPath("$.grants[1].host").value("localhost"))
                    .andExpect(jsonPath("$.grants[1].table").value("orders"))
                    .andExpect(jsonPath("$.grants[1].privileges[1]").value("INSERT"));
        }

        @Test
        void returnsEmptyGrantsWhenUserHasNone() throws Exception {
            when(permissionService.getPermissionsForUser("sourabh")).thenReturn(List.of());

            mockMvc.perform(get("/permissions/sourabh"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.grants").isEmpty());
        }

        @Test
        void acceptsUsernameWithDot() throws Exception {
            when(permissionService.getPermissionsForUser("sourabh.dev")).thenReturn(List.of());

            mockMvc.perform(get("/permissions/sourabh.dev"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value("sourabh.dev"));

            verify(permissionService).getPermissionsForUser("sourabh.dev");
        }

        @ParameterizedTest
        @ValueSource(strings = {"bad'name", "bad name", "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"})
        void rejectsInvalidUsername(String username) throws Exception {
            mockMvc.perform(get("/permissions/{username}", username))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                    .andExpect(jsonPath("$.errorCode").value("VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.action").value(ErrorCode.VALIDATION_FAILED.getAction()));

            verifyNoInteractions(permissionService);
        }
    }

    static Stream<Arguments> validRequests() {
        return forEachEndpoint(Stream.of(
                Arguments.of("mixed-case privileges", new PermissionChangeRequest("sourabh", "shop", "orders", List.of("select", "Insert"))),
                Arguments.of("ALL", new PermissionChangeRequest("sourabh", "shop", "orders", List.of("ALL"))),
                Arguments.of("CREATE, DROP, ALTER", new PermissionChangeRequest("sourabh", "shop", "orders", List.of("create", "DROP", "Alter"))),
                Arguments.of("dot, hyphen and dollar in names", new PermissionChangeRequest("sourabh.dev", "my-db", "orders$2026", List.of("SELECT")))));
    }

    static Stream<Arguments> invalidFields() {
        String username = "must be a valid username";
        String database = "must be a valid database name";
        String table = "must be a valid table name";
        return forEachEndpoint(Stream.of(
                Arguments.of("username injection", body("sourabh'@'%' WITH GRANT OPTION #", "shop", "orders", "[\"SELECT\"]"), "username", username),
                Arguments.of("table injection", body("sourabh", "shop", "orders TO 'dinesh'@'%' #", "[\"SELECT\"]"), "table", table),
                Arguments.of("database wildcard", body("sourabh", "*", "orders", "[\"SELECT\"]"), "database", database),
                Arguments.of("table wildcard", body("sourabh", "shop", "*", "[\"SELECT\"]"), "table", table),
                Arguments.of("blank username", body("", "shop", "orders", "[\"SELECT\"]"), "username", username),
                Arguments.of("blank database", body("sourabh", "", "orders", "[\"SELECT\"]"), "database", database),
                Arguments.of("whitespace table", body("sourabh", "shop", "  ", "[\"SELECT\"]"), "table", table),
                Arguments.of("space in table", body("sourabh", "shop", "order by", "[\"SELECT\"]"), "table", table),
                Arguments.of("table over 64 chars", body("sourabh", "shop", "t".repeat(65), "[\"SELECT\"]"), "table", table),
                Arguments.of("username over 80 chars", body("u".repeat(81), "shop", "orders", "[\"SELECT\"]"), "username", username),
                Arguments.of("unsupported privilege", body("sourabh", "shop", "orders", "[\"SELECT\", \"EXECUTE\"]"), "permissions[1]",
                        "must be one of: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, ALL")));
    }

    static Stream<Arguments> unreadableBodies() {
        return forEachEndpoint(Stream.of(Arguments.of("{not json"), Arguments.of("")));
    }

    static Stream<Arguments> serviceErrors() {
        return forEachEndpoint(Arrays.stream(ErrorCode.values()).map(Arguments::of));
    }

    private static Stream<Arguments> forEachEndpoint(Stream<Arguments> cases) {
        List<Arguments> caseList = cases.toList();
        return Arrays.stream(Endpoint.values()).flatMap(endpoint -> caseList.stream()
                .map(c -> {
                    Object[] values = new Object[c.get().length + 1];
                    values[0] = endpoint;
                    System.arraycopy(c.get(), 0, values, 1, c.get().length);
                    return Arguments.of(values);
                }));
    }

    private ResultActions send(Endpoint endpoint, String body) throws Exception {
        return mockMvc.perform(post(endpoint.path)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private static String body(PermissionChangeRequest request) {
        String permissions = request.permissions().stream()
                .map(p -> "\"" + p + "\"")
                .collect(Collectors.joining(", ", "[", "]"));
        return body(request.username(), request.database(), request.table(), permissions);
    }

    private static String body(String username, String database, String table, String permissions) {
        return "{\"username\": \"" + username + "\","
                + " \"database\": \"" + database + "\","
                + " \"table\": \"" + table + "\","
                + " \"permissions\": " + permissions + "}";
    }
}
