package com.db.permission.repository;

import java.sql.SQLException;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mariadb.MariaDBContainer;

import com.db.permission.dto.Privilege;
import com.db.permission.dto.TableGrant;

@JdbcTest
@Testcontainers
@Import(PermissionRepository.class)
class PermissionRepositoryTest {

    @Container
    @ServiceConnection
    static MariaDBContainer mariadb = new MariaDBContainer("mariadb:11.4")
            .withUsername("root")
            .withPassword("test");

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("CREATE DATABASE IF NOT EXISTS shop");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS shop.orders (id BIGINT PRIMARY KEY)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS shop.customers (id BIGINT PRIMARY KEY)");
        jdbcTemplate.execute("CREATE DATABASE IF NOT EXISTS `my-db`");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS `my-db`.t (id BIGINT PRIMARY KEY)");
        for (String account : List.of("'sourabh'@'%'", "'sourabh'@'localhost'", "'sourabh.dev'@'%'", "'app-user'@'%'")) {
            jdbcTemplate.execute("CREATE USER IF NOT EXISTS " + account);
            jdbcTemplate.execute("REVOKE ALL PRIVILEGES, GRANT OPTION FROM " + account);
        }
    }

    @Nested
    class Grant {

        static Stream<Arguments> privileges() {
            return Stream.of(
                    Arguments.of(EnumSet.of(Privilege.SELECT, Privilege.INSERT), List.of("SELECT", "INSERT")),
                    Arguments.of(EnumSet.of(Privilege.CREATE, Privilege.DROP, Privilege.ALTER), List.of("CREATE", "DROP", "ALTER")));
        }

        @ParameterizedTest
        @MethodSource("privileges")
        void grantsAllPrivilegesInOneStatement(EnumSet<Privilege> privileges, List<String> expected) {
            permissionRepository.grant("sourabh", "shop", "orders", privileges);

            assertThat(tablePrivileges("sourabh", "shop", "orders")).containsExactlyInAnyOrderElementsOf(expected);
        }

        static Stream<EnumSet<Privilege>> allPrivileges() {
            return Stream.of(EnumSet.of(Privilege.ALL), EnumSet.of(Privilege.SELECT, Privilege.ALL));
        }

        @ParameterizedTest
        @MethodSource("allPrivileges")
        void grantsAllPrivilegesWithoutGrantOption(EnumSet<Privilege> privileges) {
            permissionRepository.grant("sourabh", "shop", "orders", privileges);

            assertThat(tablePrivileges("sourabh", "shop", "orders"))
                    .contains("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER")
                    .doesNotContain("GRANT OPTION");
        }

        @ParameterizedTest
        @MethodSource("com.db.permission.repository.PermissionRepositoryTest#namesThatNeedQuoting")
        void quotesNamesThatNeedQuoting(String username, String database, String table) {
            permissionRepository.grant(username, database, table, EnumSet.of(Privilege.SELECT));

            assertThat(tablePrivileges(username, database, table)).containsExactly("SELECT");
        }
    }

    @Nested
    class Revoke {

        @Test
        void revokesOnlyTheGivenPrivileges() {
            jdbcTemplate.execute("GRANT SELECT, INSERT, UPDATE, DROP, ALTER ON shop.orders TO 'sourabh'@'%'");

            permissionRepository.revoke("sourabh", "shop", "orders",
                    EnumSet.of(Privilege.INSERT, Privilege.UPDATE, Privilege.DROP, Privilege.ALTER));

            assertThat(tablePrivileges("sourabh", "shop", "orders")).containsExactly("SELECT");
        }

        @Test
        void revokesAllPrivileges() {
            jdbcTemplate.execute("GRANT SELECT, INSERT, DELETE ON shop.orders TO 'sourabh'@'%'");

            permissionRepository.revoke("sourabh", "shop", "orders", EnumSet.of(Privilege.ALL));

            assertThat(tablePrivileges("sourabh", "shop", "orders")).isEmpty();
        }

        @Test
        void keepsOtherPrivilegesWhenRevokingOneNotHeld() {
            jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh'@'%'");

            permissionRepository.revoke("sourabh", "shop", "orders", EnumSet.of(Privilege.DELETE));

            assertThat(tablePrivileges("sourabh", "shop", "orders")).containsExactly("SELECT");
        }

        @ParameterizedTest
        @MethodSource("com.db.permission.repository.PermissionRepositoryTest#namesThatNeedQuoting")
        void quotesNamesThatNeedQuoting(String username, String database, String table) {
            jdbcTemplate.execute("GRANT SELECT ON `" + database + "`.`" + table + "` TO '" + username + "'@'%'");

            permissionRepository.revoke(username, database, table, EnumSet.of(Privilege.SELECT));

            assertThat(tablePrivileges(username, database, table)).isEmpty();
        }

        static Stream<Arguments> missingGrants() {
            return Stream.of(
                    Arguments.of("no grant on table", "sourabh", "customers", 1147),
                    Arguments.of("unknown user", "ghost", "orders", 1141));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("missingGrants")
        void failsWhenThereIsNothingToRevoke(String label, String username, String table, int expectedErrorCode) {
            jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh'@'%'");

            assertThatThrownBy(() -> permissionRepository.revoke(username, "shop", table, EnumSet.of(Privilege.SELECT)))
                    .isInstanceOf(DataAccessException.class)
                    .satisfies(e -> assertThat(((SQLException) e.getCause()).getErrorCode()).isEqualTo(expectedErrorCode));
        }
    }

    @Nested
    class FindGrantsByUsername {

        @Test
        void returnsTableGrantsOrderedByDatabaseAndTable() {
            jdbcTemplate.execute("GRANT SELECT, INSERT ON shop.orders TO 'sourabh'@'%'");
            jdbcTemplate.execute("GRANT UPDATE ON shop.customers TO 'sourabh'@'%'");

            List<TableGrant> grants = permissionRepository.findGrantsByUsername("sourabh");

            assertThat(grants).extracting(TableGrant::table).containsExactly("customers", "orders");
            assertThat(grants.get(0).privileges()).containsExactly("UPDATE");
            assertThat(grants.get(1).privileges()).containsExactlyInAnyOrder("SELECT", "INSERT");
        }

        @Test
        void identifiesHostOfEachGrant() {
            jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh'@'%'");
            jdbcTemplate.execute("GRANT DELETE ON shop.orders TO 'sourabh'@'localhost'");

            assertThat(permissionRepository.findGrantsByUsername("sourabh"))
                    .extracting(TableGrant::host, TableGrant::privileges)
                    .containsExactlyInAnyOrder(
                            tuple("%", List.of("SELECT")),
                            tuple("localhost", List.of("DELETE")));
        }

        @Test
        void doesNotListGrantOptionAsPrivilege() {
            jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh'@'%' WITH GRANT OPTION");

            assertThat(permissionRepository.findGrantsByUsername("sourabh").getFirst().privileges())
                    .containsExactly("SELECT");
        }

        @Test
        void supportsUsernameWithDot() {
            jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh.dev'@'%'");

            assertThat(permissionRepository.findGrantsByUsername("sourabh.dev"))
                    .singleElement()
                    .satisfies(grant -> assertThat(grant.privileges()).containsExactly("SELECT"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"ghost", "SOURABH"})
        void returnsEmptyForUnknownOrDifferentlyCasedUser(String username) {
            jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh'@'%'");

            assertThat(permissionRepository.findGrantsByUsername(username)).isEmpty();
        }

        @Test
        void doesNotIncludeDatabaseLevelGrants() {
            jdbcTemplate.execute("GRANT SELECT ON shop.* TO 'sourabh'@'%'");

            assertThat(permissionRepository.findGrantsByUsername("sourabh")).isEmpty();
        }
    }

    @Nested
    class GetAllTablesInDatabase {

        @Test
        void returnsTablesOfThatDatabase() {
            assertThat(permissionRepository.getAllTablesInDatabase("shop")).containsExactlyInAnyOrder("orders", "customers");
        }

        @Test
        void returnsEmptyForMissingDatabase() {
            assertThat(permissionRepository.getAllTablesInDatabase("nodb")).isEmpty();
        }
    }

    static Stream<Arguments> namesThatNeedQuoting() {
        return Stream.of(
                Arguments.of("sourabh.dev", "shop", "orders"),
                Arguments.of("app-user", "shop", "orders"),
                Arguments.of("sourabh", "my-db", "t"));
    }

    private List<String> tablePrivileges(String username, String database, String table) {
        return jdbcTemplate.queryForList("""
                SELECT PRIVILEGE_TYPE
                FROM information_schema.TABLE_PRIVILEGES
                WHERE GRANTEE = ? AND TABLE_SCHEMA = ? AND TABLE_NAME = ?
                """, String.class, "'" + username + "'@'%'", database, table);
    }
}
