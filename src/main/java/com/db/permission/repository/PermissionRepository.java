package com.db.permission.repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.db.permission.dto.Privilege;
import com.db.permission.dto.TableGrant;

@Repository
public class PermissionRepository {

    private static final Logger log = LoggerFactory.getLogger(PermissionRepository.class);

    private static final String FIND_GRANTS = """
            SELECT Host, Db, Table_name, Table_priv
            FROM mysql.tables_priv
            WHERE User = ? AND Table_priv <> ''
            ORDER BY Host, Db, Table_name
            """;

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

    public List<TableGrant> findGrantsByUsername(String username) {
        return jdbcTemplate.query(FIND_GRANTS, (rs, rowNum) -> new TableGrant(
                rs.getString("Host"),
                rs.getString("Db"),
                rs.getString("Table_name"),
                parsePrivileges(rs.getString("Table_priv"))), username);
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

    static List<String> parsePrivileges(String tablePriv) {
        if (tablePriv == null || tablePriv.isBlank()) {
            return Collections.emptyList();
        }

        return Arrays.stream(tablePriv.split(","))
                .map(p -> p.trim().toUpperCase())
                .map(PermissionRepository::fromStringSafely)
                .flatMap(Optional::stream)
                .map(Privilege::toString)
                .distinct()
                .toList();
    }

    private static Optional<Privilege> fromStringSafely(String input) {
        try {
            return Optional.of(Privilege.valueOf(input));
        } catch (IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }
}
