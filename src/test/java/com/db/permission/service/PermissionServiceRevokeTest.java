package com.db.permission.service;

import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTransientConnectionException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;

import com.db.permission.config.PermissionServiceProperties;
import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.Privilege;
import com.db.permission.exception.ErrorCode;
import com.db.permission.exception.PermissionException;
import com.db.permission.repository.PermissionRepository;

@ExtendWith(MockitoExtension.class)
class PermissionServiceRevokeTest {

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
        // Most tests target shop.orders; the existence-check tests override this.
        lenient().when(permissionRepository.getAllTablesInDatabase("shop")).thenReturn(Set.of("orders", "customers"));
    }

    @Test
    void revokePermissionDelegatesToRepositoryAndReturnsRevokedPrivileges() {
        EnumSet<Privilege> revoked = permissionService.revokePermission(REQUEST);

        verify(permissionRepository).revoke("sourabh", "shop", "orders", SELECT_INSERT);
        assertThat(revoked).isEqualTo(SELECT_INSERT);
    }

    @Test
    void revokePermissionNormalizesAndDeduplicatesPrivileges() {
        permissionService.revokePermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("select", "INSERT", "Select")));

        verify(permissionRepository).revoke("sourabh", "shop", "orders", SELECT_INSERT);
    }

    @Test
    void revokePermissionSupportsCreateDropAndAlter() {
        EnumSet<Privilege> revoked = permissionService.revokePermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("drop", "Create", "ALTER")));

        EnumSet<Privilege> expected = EnumSet.of(Privilege.CREATE, Privilege.DROP, Privilege.ALTER);
        verify(permissionRepository).revoke("sourabh", "shop", "orders", expected);
        assertThat(revoked).isEqualTo(expected);
    }

    @Test
    void revokePermissionCollapsesAllWithOtherPrivilegesToAll() {
        EnumSet<Privilege> revoked = permissionService.revokePermission(
                new PermissionChangeRequest("sourabh", "shop", "orders", List.of("DELETE", "all")));

        verify(permissionRepository).revoke("sourabh", "shop", "orders", EnumSet.of(Privilege.ALL));
        assertThat(revoked).containsExactly(Privilege.ALL);
    }

    static Stream<Arguments> invalidRequests() {
        return Stream.of(
                Arguments.of("username injection", new PermissionChangeRequest("sourabh'@'%' #", "shop", "orders", List.of("SELECT"))),
                Arguments.of("table injection", new PermissionChangeRequest("sourabh", "shop", "orders FROM 'dinesh'@'%' #", List.of("SELECT"))),
                Arguments.of("database wildcard", new PermissionChangeRequest("sourabh", "*", "orders", List.of("SELECT"))),
                Arguments.of("table wildcard", new PermissionChangeRequest("sourabh", "shop", "*", List.of("SELECT"))),
                Arguments.of("blank username", new PermissionChangeRequest("", "shop", "orders", List.of("SELECT"))),
                Arguments.of("unsupported privilege", new PermissionChangeRequest("sourabh", "shop", "orders", List.of("EXECUTE"))),
                Arguments.of("empty privileges", new PermissionChangeRequest("sourabh", "shop", "orders", List.of())));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidRequests")
    void revokePermissionRejectsInvalidArgumentsWithoutCallingRepository(String label, PermissionChangeRequest request) {
        assertThatThrownBy(() -> permissionService.revokePermission(request))
                .isInstanceOf(PermissionException.class)
                .extracting("errorCode").isEqualTo(ErrorCode.INVALID_ARGUMENTS);

        verifyNoInteractions(permissionRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"root", "mariadb.sys"})
    void revokePermissionRejectsProtectedUser(String username) {
        assertThatThrownBy(() -> permissionService.revokePermission(
                new PermissionChangeRequest(username, "shop", "orders", List.of("SELECT"))))
                .isInstanceOf(PermissionException.class)
                .extracting("errorCode").isEqualTo(ErrorCode.PROTECTED_ACCOUNT);

        verifyNoInteractions(permissionRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"mysql", "information_schema", "performance_schema", "sys"})
    void revokePermissionRejectsRestrictedSchema(String database) {
        assertThatThrownBy(() -> permissionService.revokePermission(
                new PermissionChangeRequest("sourabh", database, "user", List.of("SELECT"))))
                .isInstanceOf(PermissionException.class)
                .extracting("errorCode").isEqualTo(ErrorCode.SCHEMA_NOT_ALLOWED);

        verifyNoInteractions(permissionRepository);
    }

    @ParameterizedTest
    @ValueSource(ints = {1141, 1147})
    void revokePermissionMapsMissingGrantToGrantNotFound(int dbErrorCode) {
        doThrow(new BadSqlGrammarException("revoke", "REVOKE SELECT, INSERT ON `shop`.`orders` FROM `sourabh`",
                new SQLSyntaxErrorException("There is no such grant defined", "42000", dbErrorCode)))
                .when(permissionRepository).revoke("sourabh", "shop", "orders", SELECT_INSERT);

        assertThatThrownBy(() -> permissionService.revokePermission(REQUEST))
                .isInstanceOf(PermissionException.class)
                .hasMessageContaining("sourabh")
                .hasMessageContaining("orders")
                .extracting("errorCode").isEqualTo(ErrorCode.GRANT_NOT_FOUND);
    }

    @Test
    void revokePermissionMapsConnectionFailureToDatabaseUnavailable() {
        doThrow(new CannotGetJdbcConnectionException("Failed to obtain JDBC Connection",
                new SQLTransientConnectionException("Connection is not available, request timed out after 30000ms")))
                .when(permissionRepository).revoke("sourabh", "shop", "orders", SELECT_INSERT);

        assertThatThrownBy(() -> permissionService.revokePermission(REQUEST))
                .isInstanceOf(PermissionException.class)
                .extracting("errorCode").isEqualTo(ErrorCode.DATABASE_UNAVAILABLE);
    }

    @Test
    void revokePermissionMapsUnexpectedExceptionToInternalError() {
        doThrow(new IllegalStateException("boom"))
                .when(permissionRepository).revoke("sourabh", "shop", "orders", SELECT_INSERT);

        assertThatThrownBy(() -> permissionService.revokePermission(REQUEST))
                .isInstanceOf(PermissionException.class)
                .extracting("errorCode").isEqualTo(ErrorCode.INTERNAL_ERROR);
    }

    @Test
    void revokePermissionRethrowsPermissionExceptionFromRepository() {
        PermissionException rejected = new PermissionException(ErrorCode.INVALID_ARGUMENTS, "rejected");
        doThrow(rejected).when(permissionRepository).revoke(any(), any(), any(), any());

        assertThatThrownBy(() -> permissionService.revokePermission(REQUEST)).isSameAs(rejected);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"SELECT", "ALL"})
    void revokePermissionRejectsMissingTableBeforeRevoking(String privilege) {
        assertThatThrownBy(() -> permissionService.revokePermission(
                new PermissionChangeRequest("sourabh", "shop", "orders1", List.of(privilege))))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Invalid database or table name provided. Please check and try again")
                .extracting("errorCode").isEqualTo(ErrorCode.TABLE_NOT_FOUND);

        verify(permissionRepository, never()).revoke(any(), any(), any(), any());
    }

    @Test
    void revokePermissionRejectsMissingDatabaseBeforeRevoking() {
        when(permissionRepository.getAllTablesInDatabase("nodb")).thenReturn(Set.of());

        assertThatThrownBy(() -> permissionService.revokePermission(
                new PermissionChangeRequest("sourabh", "nodb", "orders", List.of("ALL"))))
                .isInstanceOf(PermissionException.class)
                .hasMessage("Invalid database or table name provided. Please check and try again")
                .extracting("errorCode").isEqualTo(ErrorCode.TABLE_NOT_FOUND);

        verify(permissionRepository, never()).revoke(any(), any(), any(), any());
    }

    @Test
    void revokePermissionMatchesTableNameExactly() {
        assertThatThrownBy(() -> permissionService.revokePermission(
                new PermissionChangeRequest("sourabh", "shop", "Orders", List.of("SELECT"))))
                .extracting("errorCode").isEqualTo(ErrorCode.TABLE_NOT_FOUND);

        verify(permissionRepository, never()).revoke(any(), any(), any(), any());
    }
}
