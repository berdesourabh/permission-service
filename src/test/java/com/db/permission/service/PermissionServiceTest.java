package com.db.permission.service;

import java.sql.SQLInvalidAuthorizationSpecException;
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
import org.junit.jupiter.api.Nested;
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
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;

import com.db.permission.config.PermissionServiceProperties;
import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.Privilege;
import com.db.permission.dto.TableGrant;
import com.db.permission.exception.ErrorCode;
import com.db.permission.exception.PermissionException;
import com.db.permission.repository.PermissionRepository;

@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    private static final String INVALID_ARGUMENTS = "Invalid arguments provided. Please check the request parameters and try again.";
    private static final String MISSING_TABLE = "Invalid database or table name provided. Please check and try again";
    private static final PermissionChangeRequest REQUEST = request("SELECT", "INSERT");
    private static final EnumSet<Privilege> SELECT_INSERT = EnumSet.of(Privilege.SELECT, Privilege.INSERT);

    @Mock
    private PermissionRepository permissionRepository;

    private PermissionService permissionService;

    @BeforeEach
    void setUp() {
        // Spring binds these lists as ArrayList, which allows contains(null); List.of would not.
        permissionService = new PermissionService(permissionRepository, new PermissionServiceProperties(
                new ArrayList<>(List.of("mysql", "information_schema", "performance_schema", "sys")),
                new ArrayList<>(List.of("root", "mariadb.sys"))));
        lenient().when(permissionRepository.getAllTablesInDatabase("shop")).thenReturn(Set.of("orders", "customers"));
    }

    @Nested
    class Grant {

        @ParameterizedTest
        @MethodSource("com.db.permission.service.PermissionServiceTest#normalizedPrivileges")
        void grantsNormalizedPrivileges(List<String> requested, EnumSet<Privilege> expected) {
            EnumSet<Privilege> granted = permissionService.grantPermission(request(requested));

            verify(permissionRepository).grant("sourabh", "shop", "orders", expected);
            assertThat(granted).isEqualTo(expected);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("com.db.permission.service.PermissionServiceTest#invalidRequests")
        void rejectsInvalidArguments(String label, PermissionChangeRequest request) {
            assertThatThrownBy(() -> permissionService.grantPermission(request))
                    .isInstanceOf(PermissionException.class)
                    .hasMessage(INVALID_ARGUMENTS)
                    .extracting("errorCode").isEqualTo(ErrorCode.INVALID_ARGUMENTS);

            verifyNoInteractions(permissionRepository);
        }

        @ParameterizedTest
        @ValueSource(strings = {"root", "mariadb.sys"})
        void rejectsProtectedUser(String username) {
            assertThatThrownBy(() -> permissionService.grantPermission(
                    new PermissionChangeRequest(username, "shop", "orders", List.of("SELECT"))))
                    .isInstanceOf(PermissionException.class)
                    .hasMessage("User '" + username + "' is protected and cannot be changed through this service.")
                    .extracting("errorCode").isEqualTo(ErrorCode.PROTECTED_ACCOUNT);

            verifyNoInteractions(permissionRepository);
        }

        @ParameterizedTest
        @ValueSource(strings = {"mysql", "information_schema", "performance_schema", "sys"})
        void rejectsRestrictedSchema(String database) {
            assertThatThrownBy(() -> permissionService.grantPermission(
                    new PermissionChangeRequest("sourabh", database, "user", List.of("SELECT"))))
                    .isInstanceOf(PermissionException.class)
                    .hasMessage("Database '" + database + "' is a restricted schema and cannot be managed through this service.")
                    .extracting("errorCode").isEqualTo(ErrorCode.SCHEMA_NOT_ALLOWED);

            verifyNoInteractions(permissionRepository);
        }

        @Test
        void usesConfiguredRestrictionLists() {
            PermissionService custom = new PermissionService(permissionRepository, new PermissionServiceProperties(
                    new ArrayList<>(List.of("billing")), new ArrayList<>(List.of("svc_admin"))));

            assertThatThrownBy(() -> custom.grantPermission(
                    new PermissionChangeRequest("sourabh", "billing", "invoices", List.of("SELECT"))))
                    .extracting("errorCode").isEqualTo(ErrorCode.SCHEMA_NOT_ALLOWED);
            assertThatThrownBy(() -> custom.grantPermission(
                    new PermissionChangeRequest("svc_admin", "shop", "orders", List.of("SELECT"))))
                    .extracting("errorCode").isEqualTo(ErrorCode.PROTECTED_ACCOUNT);
            verifyNoInteractions(permissionRepository);
        }

        @ParameterizedTest(name = "{0}.{1} with {2}")
        @MethodSource("com.db.permission.service.PermissionServiceTest#missingTables")
        void rejectsMissingTableBeforeGranting(String database, String table, String privilege) {
            lenient().when(permissionRepository.getAllTablesInDatabase("nodb")).thenReturn(Set.of());

            assertThatThrownBy(() -> permissionService.grantPermission(
                    new PermissionChangeRequest("sourabh", database, table, List.of(privilege))))
                    .isInstanceOf(PermissionException.class)
                    .hasMessage(MISSING_TABLE)
                    .extracting("errorCode").isEqualTo(ErrorCode.TABLE_NOT_FOUND);

            verify(permissionRepository, never()).grant(any(), any(), any(), any());
        }

        @ParameterizedTest(name = "{1}")
        @MethodSource("com.db.permission.service.PermissionServiceTest#repositoryFailures")
        void mapsRepositoryFailures(Exception failure, ErrorCode expectedCode, String expectedMessage) {
            doThrow(failure).when(permissionRepository).grant(any(), any(), any(), any());

            assertThatThrownBy(() -> permissionService.grantPermission(REQUEST))
                    .isInstanceOf(PermissionException.class)
                    .hasMessage(expectedMessage)
                    .extracting("errorCode").isEqualTo(expectedCode);
        }

        @Test
        void rethrowsPermissionExceptionFromRepository() {
            PermissionException rejected = new PermissionException(ErrorCode.INVALID_ARGUMENTS, "rejected");
            doThrow(rejected).when(permissionRepository).grant(any(), any(), any(), any());

            assertThatThrownBy(() -> permissionService.grantPermission(REQUEST)).isSameAs(rejected);
        }
    }

    @Nested
    class Revoke {

        @ParameterizedTest
        @MethodSource("com.db.permission.service.PermissionServiceTest#normalizedPrivileges")
        void revokesNormalizedPrivileges(List<String> requested, EnumSet<Privilege> expected) {
            EnumSet<Privilege> revoked = permissionService.revokePermission(request(requested));

            verify(permissionRepository).revoke("sourabh", "shop", "orders", expected);
            assertThat(revoked).isEqualTo(expected);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("com.db.permission.service.PermissionServiceTest#invalidRequests")
        void rejectsInvalidArguments(String label, PermissionChangeRequest request) {
            assertThatThrownBy(() -> permissionService.revokePermission(request))
                    .isInstanceOf(PermissionException.class)
                    .hasMessage(INVALID_ARGUMENTS)
                    .extracting("errorCode").isEqualTo(ErrorCode.INVALID_ARGUMENTS);

            verifyNoInteractions(permissionRepository);
        }

        @ParameterizedTest
        @ValueSource(strings = {"root", "mariadb.sys"})
        void rejectsProtectedUser(String username) {
            assertThatThrownBy(() -> permissionService.revokePermission(
                    new PermissionChangeRequest(username, "shop", "orders", List.of("SELECT"))))
                    .isInstanceOf(PermissionException.class)
                    .extracting("errorCode").isEqualTo(ErrorCode.PROTECTED_ACCOUNT);

            verifyNoInteractions(permissionRepository);
        }

        @ParameterizedTest
        @ValueSource(strings = {"mysql", "information_schema", "performance_schema", "sys"})
        void rejectsRestrictedSchema(String database) {
            assertThatThrownBy(() -> permissionService.revokePermission(
                    new PermissionChangeRequest("sourabh", database, "user", List.of("SELECT"))))
                    .isInstanceOf(PermissionException.class)
                    .extracting("errorCode").isEqualTo(ErrorCode.SCHEMA_NOT_ALLOWED);

            verifyNoInteractions(permissionRepository);
        }

        @ParameterizedTest(name = "{0}.{1} with {2}")
        @MethodSource("com.db.permission.service.PermissionServiceTest#missingTables")
        void rejectsMissingTableBeforeRevoking(String database, String table, String privilege) {
            lenient().when(permissionRepository.getAllTablesInDatabase("nodb")).thenReturn(Set.of());

            assertThatThrownBy(() -> permissionService.revokePermission(
                    new PermissionChangeRequest("sourabh", database, table, List.of(privilege))))
                    .isInstanceOf(PermissionException.class)
                    .hasMessage(MISSING_TABLE)
                    .extracting("errorCode").isEqualTo(ErrorCode.TABLE_NOT_FOUND);

            verify(permissionRepository, never()).revoke(any(), any(), any(), any());
        }

        @ParameterizedTest(name = "{1}")
        @MethodSource("com.db.permission.service.PermissionServiceTest#repositoryFailures")
        void mapsRepositoryFailures(Exception failure, ErrorCode expectedCode, String expectedMessage) {
            doThrow(failure).when(permissionRepository).revoke(any(), any(), any(), any());

            assertThatThrownBy(() -> permissionService.revokePermission(REQUEST))
                    .isInstanceOf(PermissionException.class)
                    .hasMessage(expectedMessage)
                    .extracting("errorCode").isEqualTo(expectedCode);
        }

        @Test
        void rethrowsPermissionExceptionFromRepository() {
            PermissionException rejected = new PermissionException(ErrorCode.INVALID_ARGUMENTS, "rejected");
            doThrow(rejected).when(permissionRepository).revoke(any(), any(), any(), any());

            assertThatThrownBy(() -> permissionService.revokePermission(REQUEST)).isSameAs(rejected);
        }
    }

    @Nested
    class GetPermissionsForUser {

        @Test
        void returnsGrantsFromRepository() {
            List<TableGrant> grants = List.of(new TableGrant("%", "shop", "orders", List.of("SELECT", "INSERT")));
            when(permissionRepository.findGrantsByUsername("sourabh")).thenReturn(grants);

            assertThat(permissionService.getPermissionsForUser("sourabh")).isEqualTo(grants);
        }

        @Test
        void returnsEmptyListWhenUserHasNoGrants() {
            when(permissionRepository.findGrantsByUsername("sourabh")).thenReturn(List.of());

            assertThat(permissionService.getPermissionsForUser("sourabh")).isEmpty();
        }

        @Test
        void mapsConnectionFailureToDatabaseUnavailable() {
            when(permissionRepository.findGrantsByUsername("sourabh")).thenThrow(connectionFailure());

            assertThatThrownBy(() -> permissionService.getPermissionsForUser("sourabh"))
                    .isInstanceOf(PermissionException.class)
                    .extracting("errorCode").isEqualTo(ErrorCode.DATABASE_UNAVAILABLE);
        }

        @Test
        void doesNotExposeRawDatabaseMessage() {
            when(permissionRepository.findGrantsByUsername("sourabh")).thenThrow(new BadSqlGrammarException(
                    "select", "SELECT Host, Db, Table_name, Table_priv FROM mysql.tables_priv WHERE User = ?",
                    new SQLSyntaxErrorException("SELECT command denied to user 'perm_svc'@'10.0.0.5' for table 'tables_priv'",
                            "42000", 1142)));

            assertThatThrownBy(() -> permissionService.getPermissionsForUser("sourabh"))
                    .isInstanceOf(PermissionException.class)
                    .satisfies(e -> assertThat(e.getMessage())
                            .doesNotContain("tables_priv", "perm_svc", "10.0.0.5", "SELECT command denied"));
        }
    }

    static Stream<Arguments> normalizedPrivileges() {
        return Stream.of(
                Arguments.of(List.of("SELECT", "INSERT"), SELECT_INSERT),
                Arguments.of(List.of("select", "INSERT", "Select"), SELECT_INSERT),
                Arguments.of(List.of("drop", "Create", "ALTER"), EnumSet.of(Privilege.CREATE, Privilege.DROP, Privilege.ALTER)),
                Arguments.of(List.of("all"), EnumSet.of(Privilege.ALL)),
                Arguments.of(List.of("SELECT", "ALL"), EnumSet.of(Privilege.ALL)));
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
                Arguments.of("username over 80 chars", new PermissionChangeRequest("u".repeat(81), "shop", "orders", List.of("SELECT"))),
                Arguments.of("unsupported privilege", new PermissionChangeRequest("sourabh", "shop", "orders", List.of("EXECUTE"))),
                Arguments.of("empty privileges", new PermissionChangeRequest("sourabh", "shop", "orders", List.of())));
    }

    static Stream<Arguments> missingTables() {
        return Stream.of(
                Arguments.of("shop", "orders1", "SELECT"),
                Arguments.of("shop", "orders1", "ALL"),
                Arguments.of("shop", "Orders", "SELECT"),
                Arguments.of("nodb", "orders", "ALL"));
    }

    static Stream<Arguments> repositoryFailures() {
        String sql = "GRANT SELECT, INSERT ON `shop`.`orders` TO `sourabh`";
        return Stream.of(
                Arguments.of(new BadSqlGrammarException("grant", sql,
                        new SQLSyntaxErrorException("Table 'shop.orders' doesn't exist", "42S02", 1146)),
                        ErrorCode.TABLE_NOT_FOUND, "Database shop or table orders does not exist."),
                Arguments.of(new PermissionDeniedDataAccessException("grant",
                        new SQLInvalidAuthorizationSpecException("Can't find any matching row in the user table", "28000", 1133)),
                        ErrorCode.USER_NOT_FOUND, "Account sourabh does not exist."),
                Arguments.of(new BadSqlGrammarException("revoke", sql,
                        new SQLSyntaxErrorException("There is no such grant defined", "42000", 1147)),
                        ErrorCode.GRANT_NOT_FOUND, "sourabh has no privileges on orders to revoke, or the account does not exist."),
                Arguments.of(connectionFailure(),
                        ErrorCode.DATABASE_UNAVAILABLE, "The database could not be reached or did not respond in time."),
                Arguments.of(new IllegalStateException("boom"),
                        ErrorCode.INTERNAL_ERROR, "Unexpected database error."));
    }

    private static CannotGetJdbcConnectionException connectionFailure() {
        return new CannotGetJdbcConnectionException("Failed to obtain JDBC Connection",
                new SQLTransientConnectionException("Connection is not available, request timed out after 30000ms"));
    }

    private static PermissionChangeRequest request(String... privileges) {
        return request(List.of(privileges));
    }

    private static PermissionChangeRequest request(List<String> privileges) {
        return new PermissionChangeRequest("sourabh", "shop", "orders", privileges);
    }
}
