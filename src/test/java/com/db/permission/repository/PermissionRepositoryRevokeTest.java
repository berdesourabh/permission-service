package com.db.permission.repository;

import java.sql.SQLException;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

@JdbcTest
@Testcontainers
@Import(PermissionRepository.class)
class PermissionRepositoryRevokeTest {

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
        jdbcTemplate.execute("CREATE USER IF NOT EXISTS 'sourabh'@'%' IDENTIFIED BY 'sourabh'");
        jdbcTemplate.execute("CREATE USER IF NOT EXISTS 'sourabh.dev'@'%' IDENTIFIED BY 'sourabh'");
        jdbcTemplate.execute("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'sourabh'@'%', 'sourabh.dev'@'%'");
    }

    @Test
    void revokeRemovesOnlyTheGivenPrivileges() {
        jdbcTemplate.execute("GRANT SELECT, INSERT, UPDATE ON shop.orders TO 'sourabh'@'%'");

        permissionRepository.revoke("sourabh", "shop", "orders", EnumSet.of(Privilege.INSERT, Privilege.UPDATE));

        assertThat(tablePrivileges("sourabh", "orders")).containsExactly("SELECT");
    }

    @Test
    void revokeRemovesDropAndAlter() {
        jdbcTemplate.execute("GRANT SELECT, DROP, ALTER ON shop.orders TO 'sourabh'@'%'");

        permissionRepository.revoke("sourabh", "shop", "orders", EnumSet.of(Privilege.DROP, Privilege.ALTER));

        assertThat(tablePrivileges("sourabh", "orders")).containsExactly("SELECT");
    }

    @Test
    void revokeQuotesHyphenatedDatabaseName() {
        jdbcTemplate.execute("CREATE DATABASE IF NOT EXISTS `my-db`");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS `my-db`.t (id BIGINT PRIMARY KEY)");
        jdbcTemplate.execute("GRANT SELECT ON `my-db`.t TO 'sourabh'@'%'");

        permissionRepository.revoke("sourabh", "my-db", "t", EnumSet.of(Privilege.SELECT));

        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA = 'my-db'", Integer.class))
                .isZero();
    }

    @Test
    void revokeAllRemovesEveryTablePrivilege() {
        jdbcTemplate.execute("GRANT SELECT, INSERT, DELETE ON shop.orders TO 'sourabh'@'%'");

        permissionRepository.revoke("sourabh", "shop", "orders", EnumSet.of(Privilege.ALL));

        assertThat(tablePrivileges("sourabh", "orders")).isEmpty();
    }

    @Test
    void revokeQuotesUsernamesWithDot() {
        jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh.dev'@'%'");

        permissionRepository.revoke("sourabh.dev", "shop", "orders", EnumSet.of(Privilege.SELECT));

        assertThat(tablePrivileges("sourabh.dev", "orders")).isEmpty();
    }

    @Test
    void revokeOfPrivilegeNotHeldLeavesOtherPrivileges() {
        // MariaDB does not raise an error when the user holds other privileges on the table.
        jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh'@'%'");

        permissionRepository.revoke("sourabh", "shop", "orders", EnumSet.of(Privilege.DELETE));

        assertThat(tablePrivileges("sourabh", "orders")).containsExactly("SELECT");
    }

    @Test
    void revokeWhenUserHasNoGrantOnTableFailsWith1147() {
        jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh'@'%'");

        assertThatThrownBy(() -> permissionRepository.revoke("sourabh", "shop", "customers", EnumSet.of(Privilege.SELECT)))
                .isInstanceOf(DataAccessException.class)
                .satisfies(e -> assertThat(((SQLException) e.getCause()).getErrorCode()).isEqualTo(1147));
    }

    @Test
    void revokeFromUnknownUserFailsWith1141() {
        assertThatThrownBy(() -> permissionRepository.revoke("ghost", "shop", "orders", EnumSet.of(Privilege.SELECT)))
                .isInstanceOf(DataAccessException.class)
                .satisfies(e -> assertThat(((SQLException) e.getCause()).getErrorCode()).isEqualTo(1141));
    }

    @Test
    void revokeOnTableLeavesDatabaseLevelGrant() {
        // A table-level REVOKE does not touch db-level grants, so the user can still read the table.
        jdbcTemplate.execute("GRANT SELECT ON shop.* TO 'sourabh'@'%'");
        jdbcTemplate.execute("GRANT SELECT ON shop.orders TO 'sourabh'@'%'");

        permissionRepository.revoke("sourabh", "shop", "orders", EnumSet.of(Privilege.SELECT));

        assertThat(tablePrivileges("sourabh", "orders")).isEmpty();
        assertThat(jdbcTemplate.queryForList(
                "SELECT PRIVILEGE_TYPE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE = ? AND TABLE_SCHEMA = 'shop'",
                String.class, "'sourabh'@'%'"))
                .containsExactly("SELECT");
    }

    private List<String> tablePrivileges(String username, String table) {
        return jdbcTemplate.queryForList("""
                SELECT PRIVILEGE_TYPE
                FROM information_schema.TABLE_PRIVILEGES
                WHERE GRANTEE = ? AND TABLE_SCHEMA = 'shop' AND TABLE_NAME = ?
                """, String.class, "'" + username + "'@'%'", table);
    }
}
