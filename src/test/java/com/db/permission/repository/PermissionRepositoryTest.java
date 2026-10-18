package com.db.permission.repository;

import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mariadb.MariaDBContainer;

import com.db.permission.dto.Privilege;

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
        jdbcTemplate.execute("CREATE USER IF NOT EXISTS 'sourabh'@'%' IDENTIFIED BY 'sourabh'");
        jdbcTemplate.execute("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'sourabh'@'%'");
    }

    @Test
    void grantAddsTablePrivilegesForUser() {
        permissionRepository.grant("sourabh", "shop", "orders", EnumSet.of(Privilege.SELECT, Privilege.INSERT));

        assertThat(tablePrivileges()).containsExactlyInAnyOrder("SELECT", "INSERT");
    }

    @ParameterizedTest
    @ValueSource(strings = {"sourabh.dev", "app-user"})
    void grantQuotesUsernamesWithDotOrHyphen(String username) {
        jdbcTemplate.execute("CREATE USER IF NOT EXISTS '" + username + "'@'%'");

        permissionRepository.grant(username, "shop", "orders", EnumSet.of(Privilege.SELECT));

        assertThat(jdbcTemplate.queryForList("""
                SELECT PRIVILEGE_TYPE
                FROM information_schema.TABLE_PRIVILEGES
                WHERE GRANTEE = ? AND TABLE_SCHEMA = 'shop' AND TABLE_NAME = 'orders'
                """, String.class, "'" + username + "'@'%'"))
                .containsExactly("SELECT");
    }

    @Test
    void grantAllAddsAllTablePrivileges() {
        permissionRepository.grant("sourabh", "shop", "orders", EnumSet.of(Privilege.ALL));

        assertThat(tablePrivileges())
                .contains("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER")
                .doesNotContain("GRANT OPTION");
    }

    @Test
    void grantAllTogetherWithOtherPrivilegesGrantsAllPrivileges() {
        permissionRepository.grant("sourabh", "shop", "orders", EnumSet.of(Privilege.SELECT, Privilege.ALL));

        assertThat(tablePrivileges()).contains("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER");
    }

    @Test
    void grantQuotesHyphenatedDatabaseName() {
        jdbcTemplate.execute("CREATE DATABASE IF NOT EXISTS `my-db`");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS `my-db`.t (id BIGINT PRIMARY KEY)");

        permissionRepository.grant("sourabh", "my-db", "t", EnumSet.of(Privilege.SELECT));

        assertThat(jdbcTemplate.queryForList("""
                SELECT PRIVILEGE_TYPE
                FROM information_schema.TABLE_PRIVILEGES
                WHERE GRANTEE = '''sourabh''@''%''' AND TABLE_SCHEMA = 'my-db' AND TABLE_NAME = 't'
                """, String.class))
                .containsExactly("SELECT");
    }

    @Test
    void grantAddsCreateDropAndAlter() {
        permissionRepository.grant("sourabh", "shop", "orders", EnumSet.of(Privilege.CREATE, Privilege.DROP, Privilege.ALTER));

        assertThat(tablePrivileges()).containsExactlyInAnyOrder("CREATE", "DROP", "ALTER");
    }

    @Test
    void getAllTablesInDatabaseReturnsTablesOfThatDatabase() {
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS shop.customers (id BIGINT PRIMARY KEY)");

        assertThat(permissionRepository.getAllTablesInDatabase("shop")).contains("orders", "customers");
    }

    @Test
    void getAllTablesInDatabaseReturnsEmptyForMissingDatabase() {
        assertThat(permissionRepository.getAllTablesInDatabase("nodb")).isEmpty();
    }

    private List<String> tablePrivileges() {
        return jdbcTemplate.queryForList("""
                SELECT PRIVILEGE_TYPE
                FROM information_schema.TABLE_PRIVILEGES
                WHERE GRANTEE = ? AND TABLE_SCHEMA = ? AND TABLE_NAME = ?
                """, String.class, "'sourabh'@'%'", "shop", "orders");
    }
}
