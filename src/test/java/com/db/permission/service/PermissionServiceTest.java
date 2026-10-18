package com.db.permission.service;

import java.sql.SQLInvalidAuthorizationSpecException;
import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTransientConnectionException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;

import com.db.permission.exception.ErrorCode;
import com.db.permission.exception.PermissionException;
import com.db.permission.repository.PermissionRepository;

@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    private static final List<String> PERMISSIONS = List.of("SELECT", "INSERT");

    @Mock
    private PermissionRepository permissionRepository;

    @InjectMocks
    private PermissionService permissionService;

    @Test
    void grantPermissionDelegatesToRepository() {
        permissionService.grantPermission("sourabh", "shop", "orders", PERMISSIONS);

        verify(permissionRepository).grant("sourabh", "shop", "orders", PERMISSIONS);
    }

    @Test
    void grantPermissionMapsMissingTableToTableNotFound() {
        doThrow(new BadSqlGrammarException("grant", "GRANT SELECT ON shop.orders TO 'sourabh'",
                new SQLSyntaxErrorException("Table 'shop.orders' doesn't exist", "42S02", 1146)))
                .when(permissionRepository).grant("sourabh", "shop", "orders", PERMISSIONS);

        assertThatThrownBy(() -> permissionService.grantPermission("sourabh", "shop", "orders", PERMISSIONS))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Table orders does not exist.")
                .extracting("errorCode").isEqualTo(ErrorCode.TABLE_NOT_FOUND);
    }

    @Test
    void grantPermissionMapsMissingUserToUserNotFound() {
        doThrow(new PermissionDeniedDataAccessException("grant",
                new SQLInvalidAuthorizationSpecException("Can't find any matching row in the user table", "28000", 1133)))
                .when(permissionRepository).grant("sourabh", "shop", "orders", PERMISSIONS);

        assertThatThrownBy(() -> permissionService.grantPermission("sourabh", "shop", "orders", PERMISSIONS))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Account sourabh does not exist.")
                .extracting("errorCode").isEqualTo(ErrorCode.USER_NOT_FOUND);
    }

    @Test
    void grantPermissionMapsConnectionFailureToDatabaseUnavailable() {
        doThrow(new CannotGetJdbcConnectionException("Failed to obtain JDBC Connection",
                new SQLTransientConnectionException("Connection is not available, request timed out after 30000ms")))
                .when(permissionRepository).grant("sourabh", "shop", "orders", PERMISSIONS);

        assertThatThrownBy(() -> permissionService.grantPermission("sourabh", "shop", "orders", PERMISSIONS))
                .isInstanceOf(PermissionException.class)
                .extracting("errorCode").isEqualTo(ErrorCode.DATABASE_UNAVAILABLE);
    }

    @Test
    void grantPermissionMapsUnexpectedExceptionToInternalError() {
        doThrow(new IllegalStateException("boom"))
                .when(permissionRepository).grant("sourabh", "shop", "orders", PERMISSIONS);

        assertThatThrownBy(() -> permissionService.grantPermission("sourabh", "shop", "orders", PERMISSIONS))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Unexpected database error.")
                .extracting("errorCode").isEqualTo(ErrorCode.INTERNAL_ERROR);
    }
}
