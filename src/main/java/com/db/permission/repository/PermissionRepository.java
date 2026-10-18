package com.db.permission.repository;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.db.permission.dto.Privilege;

@Repository

public class PermissionRepository {

    private static final Logger log = LoggerFactory.getLogger(PermissionRepository.class);

    private final JdbcTemplate jdbcTemplate;

    public PermissionRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;

    }

    public void grant(String username, String database, String table, EnumSet<Privilege> permissions) {

        String sql = "GRANT " + buildPrivilegeString(permissions) + " ON " + quoteTable(database, table) + " TO " + quoteUserName(username);
        log.info("Executing SQL: {}", sql);
        jdbcTemplate.execute(sql);
    }

    public void revoke(String username, String database, String table, EnumSet<Privilege> permissions) {

        String sql = "REVOKE " + buildPrivilegeString(permissions) + " ON " + quoteTable(database, table) + " FROM " + quoteUserName(username);
        log.info("Executing SQL: {}", sql);
        jdbcTemplate.execute(sql);
    }

    public Set<String> getAllTablesInDatabase(String database) {
        String sql = "SELECT TABLE_NAME FROM information_schema.TABLES t WHERE t.TABLE_SCHEMA = ?";
        return new HashSet<>(jdbcTemplate.queryForList(sql, String.class, database));
    }

    private static String buildPrivilegeString(EnumSet<Privilege> privileges) {
        if (privileges.contains(Privilege.ALL)) {
            return "ALL PRIVILEGES";
        }
        return String.join(", ", privileges.stream().map(Privilege::name).toArray(String[]::new));
    }

    private static String quoteTable(String database, String table) {
        return "`" + database.replace("`", "``") + "`.`" + table.replace("`", "``") + "`";
    }

    private static String quoteUserName(String username) {
        return "`" + username.replace("`", "``") + "`";
    }
}
