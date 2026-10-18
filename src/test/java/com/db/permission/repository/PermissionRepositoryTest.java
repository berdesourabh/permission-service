package com.db.permission.repository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mariadb.MariaDBContainer;

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
    }

    @Test
    void grantAddsTablePrivilegesForUser() {
        permissionRepository.grant("sourabh", "shop", "orders", List.of("SELECT", "INSERT"));

        List<String> privileges = jdbcTemplate.queryForList("""
                SELECT PRIVILEGE_TYPE
                FROM information_schema.TABLE_PRIVILEGES
                WHERE GRANTEE = ? AND TABLE_SCHEMA = ? AND TABLE_NAME = ?
                """, String.class, "'sourabh'@'%'", "shop", "orders");

        assertThat(privileges).containsExactlyInAnyOrder("SELECT", "INSERT");
    }
}
