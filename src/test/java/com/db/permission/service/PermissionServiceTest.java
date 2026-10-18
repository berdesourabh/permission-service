package com.db.permission.service;

import java.sql.SQLInvalidAuthorizationSpecException;
import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTransientConnectionException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;

import com.db.permission.config.PermissionServiceProperties;
import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.Privilege;
import com.db.permission.exception.ErrorCode;
import com.db.permission.exception.PermissionException;
import com.db.permission.repository.PermissionRepository;

@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    private static final EnumSet<Privilege> SELECT_INSERT = EnumSet.of(Privilege.SELECT, Privilege.INSERT);
    private static final PermissionChangeRequest REQUEST =
            new PermissionChangeRequest("sourabh", "shop", "orders", List.of("SELECT", "INSERT"));

    @Mock
    private PermissionRepository permissionRepository;

    private PermissionService permissionService;

    @BeforeEach
    void setUp() {
        // Spring binds these lists as ArrayList, which allows contains(null); List.of would not.
        PermissionServiceProperties properties = new PermissionServiceProperties(
                new ArrayList<>(List.of("mysql", "information_schema", "performance_schema", "sys")),
                new ArrayList<>(List.of("root", "mariadb.sys")));
        permissionService = new PermissionService(permissionRepository, properties);
    }

    @Test
    void grantPermissionDelegatesToRepository() {
        EnumSet<Privilege> granted = permissionService.grantPermission(REQUEST);

        verify(permissionRepository).grant("sourabh", "shop", "orders", SELECT_INSERT);
        assertThat(granted).isEqualTo(SELECT_INSERT);
    }

    @Test
    void grantPermissionCollapsesAllWithOtherPrivilegesToAll() {
        EnumSet<Privilege> granted = permissionService.grantPermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("SELECT", "ALL")));

        verify(permissionRepository).grant("sourabh", "shop", "orders", EnumSet.of(Privilege.ALL));
        assertThat(granted).containsExactly(Privilege.ALL);
    }

    @ParameterizedTest
    @ValueSource(strings = {"root", "mariadb.sys"})
    void grantPermissionRejectsProtectedUser(String username) {
        assertThatThrownBy(() -> permissionService.grantPermission(
                new PermissionChangeRequest(username, "shop", "orders", List.of("SELECT"))))
                .isInstanceOf(PermissionException.class)
                .hasMessage("User '" + username + "' is protected and cannot be changed through this service.")
                .extracting("errorCode").isEqualTo(ErrorCode.PROTECTED_ACCOUNT);

        verifyNoInteractions(permissionRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"mysql", "information_schema", "performance_schema", "sys"})
    void grantPermissionRejectsRestrictedSchema(String database) {
        assertThatThrownBy(() -> permissionService.grantPermission(
                new PermissionChangeRequest("sourabh", database, "user", List.of("SELECT"))))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Database '" + database + "' is a restricted schema and cannot be managed through this service.")
                .extracting("errorCode").isEqualTo(ErrorCode.SCHEMA_NOT_ALLOWED);

        verifyNoInteractions(permissionRepository);
    }

    @Test
    void grantPermissionUsesConfiguredRestrictionLists() {
        PermissionService custom = new PermissionService(permissionRepository,
                new PermissionServiceProperties(new ArrayList<>(List.of("billing")), new ArrayList<>(List.of("svc_admin"))));

        assertThatThrownBy(() -> custom.grantPermission(
                new PermissionChangeRequest("sourabh", "billing", "invoices", List.of("SELECT"))))
                .extracting("errorCode").isEqualTo(ErrorCode.SCHEMA_NOT_ALLOWED);
        assertThatThrownBy(() -> custom.grantPermission(
                new PermissionChangeRequest("svc_admin", "shop", "orders", List.of("SELECT"))))
                .extracting("errorCode").isEqualTo(ErrorCode.PROTECTED_ACCOUNT);
        verifyNoInteractions(permissionRepository);
    }

    @Test
    void grantPermissionNormalizesAndDeduplicatesPrivileges() {
        permissionService.grantPermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("select", "INSERT", "Select")));

        verify(permissionRepository).grant("sourabh", "shop", "orders", SELECT_INSERT);
    }

    @Test
    void grantPermissionPassesAllPrivilegeToRepository() {
        permissionService.grantPermission(new PermissionChangeRequest("sourabh", "shop", "orders", List.of("all")));

        verify(permissionRepository).grant("sourabh", "shop", "orders", EnumSet.of(Privilege.ALL));
    }

    static Stream<Arguments> invalidRequests() {
        return Stream.of(
                Arguments.of("username injection", new PermissionChangeRequest("sourabh'@'%' WITH GRANT OPTION #", "shop", "orders", List.of("SELECT"))),
                Arguments.of("table injection", new PermissionChangeRequest("sourabh", "shop", "orders TO 'dinesh'@'%' #", List.of("SELECT"))),
                Arguments.of("database wildcard", new PermissionChangeRequest("sourabh", "*", "orders", List.of("SELECT"))),
                Arguments.of("table wildcard", new PermissionChangeRequest("sourabh", "shop", "*", List.of("SELECT"))),
                Arguments.of("blank username", new PermissionChangeRequest("", "shop", "orders", List.of("SELECT"))),
                Arguments.of("null database", new PermissionChangeRequest("sourabh", null, "orders", List.of("SELECT"))),
                Arguments.of("table over 64 chars", new PermissionChangeRequest("sourabh", "shop", "t".repeat(65), List.of("SELECT"))),
                Arguments.of("username over 80 chars", new PermissionChangeRequest("u".repeat(81), "shop", "orders", List.of("SELECT"))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidRequests")
    void grantPermissionRejectsInvalidArgumentsWithoutCallingRepository(String label, PermissionChangeRequest request) {
        assertThatThrownBy(() -> permissionService.grantPermission(request))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Invalid arguments provided. Please check the request parameters and try again.")
                .extracting("errorCode").isEqualTo(ErrorCode.INVALID_ARGUMENTS);

        verifyNoInteractions(permissionRepository);
    }

    @Test
    void grantPermissionRethrowsPermissionExceptionFromRepository() {
        PermissionException rejected = new PermissionException(ErrorCode.INVALID_ARGUMENTS, "rejected");
        doThrow(rejected).when(permissionRepository).grant(any(), any(), any(), any());

        assertThatThrownBy(() -> permissionService.grantPermission(REQUEST)).isSameAs(rejected);
    }

    @Test
    void grantPermissionMapsMissingTableToTableNotFound() {
        doThrow(new BadSqlGrammarException("grant", "GRANT SELECT, INSERT ON shop.orders TO 'sourabh'",
                new SQLSyntaxErrorException("Table 'shop.orders' doesn't exist", "42S02", 1146)))
                .when(permissionRepository).grant("sourabh", "shop", "orders", SELECT_INSERT);

        assertThatThrownBy(() -> permissionService.grantPermission(REQUEST))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Database shop or table orders does not exist.")
                .extracting("errorCode").isEqualTo(ErrorCode.TABLE_NOT_FOUND);
    }

    @Test
    void grantPermissionMapsMissingUserToUserNotFound() {
        doThrow(new PermissionDeniedDataAccessException("grant",
                new SQLInvalidAuthorizationSpecException("Can't find any matching row in the user table", "28000", 1133)))
                .when(permissionRepository).grant("sourabh", "shop", "orders", SELECT_INSERT);

        assertThatThrownBy(() -> permissionService.grantPermission(REQUEST))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Account sourabh does not exist.")
                .extracting("errorCode").isEqualTo(ErrorCode.USER_NOT_FOUND);
    }

    @Test
    void grantPermissionMapsConnectionFailureToDatabaseUnavailable() {
        doThrow(new CannotGetJdbcConnectionException("Failed to obtain JDBC Connection",
                new SQLTransientConnectionException("Connection is not available, request timed out after 30000ms")))
                .when(permissionRepository).grant("sourabh", "shop", "orders", SELECT_INSERT);

        assertThatThrownBy(() -> permissionService.grantPermission(REQUEST))
                .isInstanceOf(PermissionException.class)
                .extracting("errorCode").isEqualTo(ErrorCode.DATABASE_UNAVAILABLE);
    }

    @Test
    void grantPermissionMapsUnexpectedExceptionToInternalError() {
        doThrow(new IllegalStateException("boom"))
                .when(permissionRepository).grant("sourabh", "shop", "orders", SELECT_INSERT);

        assertThatThrownBy(() -> permissionService.grantPermission(REQUEST))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Unexpected database error.")
                .extracting("errorCode").isEqualTo(ErrorCode.INTERNAL_ERROR);
    }
}
