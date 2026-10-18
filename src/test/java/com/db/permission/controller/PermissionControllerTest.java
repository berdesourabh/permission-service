package com.db.permission.controller;

import java.util.List;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
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
        grant(VALID_REQUEST)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Permissions granted successfully"))
                .andExpect(jsonPath("$.username").value("sourabh"))
                .andExpect(jsonPath("$.database").value("shop"))
                .andExpect(jsonPath("$.table").value("orders"))
                .andExpect(jsonPath("$.permissions[0]").value("SELECT"))
                .andExpect(jsonPath("$.permissions[1]").value("INSERT"));

        verify(permissionService).grantPermission("sourabh", "shop", "orders", List.of("SELECT", "INSERT"));
    }

    @Test
    void grantAcceptsPermissionsCaseInsensitively() throws Exception {
        grant("""
                {
                  "username": "sourabh",
                  "database": "shop",
                  "table": "orders",
                  "permissions": ["select", "Insert"]
                }
                """)
                .andExpect(status().isOk());

        verify(permissionService).grantPermission("sourabh", "shop", "orders", List.of("select", "Insert"));
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
        grant("""
                {
                  "username": "sourabh",
                  "database": "shop",
                  "table": "orders",
                  "permissions": ["SELECT", "DROP"]
                }
                """)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.errors.length()").value(1))
                .andExpect(jsonPath("$.errors[0].field").value("permissions[1]"))
                .andExpect(jsonPath("$.errors[0].message")
                        .value("must be one of: SELECT, INSERT, UPDATE, DELETE, ALL"));

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
    void grantReturnsErrorCodeStatusWhenServiceThrowsPermissionException() throws Exception {
        doThrow(new PermissionException(ErrorCode.MALFORMED_REQUEST, "Table shop.orders is not valid"))
                .when(permissionService).grantPermission(any(), any(), any(), any());

        grant(VALID_REQUEST)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errorCode").value("MALFORMED_REQUEST"))
                .andExpect(jsonPath("$.detail").value("Table shop.orders is not valid"))
                .andExpect(jsonPath("$.action").value(ErrorCode.MALFORMED_REQUEST.getAction()));
    }

    @Test
    void grantReturnsInternalErrorWithoutLeakingDetailsOnUnexpectedException() throws Exception {
        doThrow(new IllegalStateException("connection refused to db-host:3306"))
                .when(permissionService).grantPermission(any(), any(), any(), any());

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
}
