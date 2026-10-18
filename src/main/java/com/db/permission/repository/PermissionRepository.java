package com.db.permission.repository;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class PermissionRepository {

    private static final Logger log = LoggerFactory.getLogger(PermissionRepository.class);

    private final JdbcTemplate jdbcTemplate;

    public PermissionRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void grant(String username, String database, String table, List<String> permissions) {
        for (String permission : permissions) {
            String sql = "GRANT " + permission + " ON " + database + "." + table + " TO '" + username + "'";
            log.info("Executing SQL: {}", sql);
            jdbcTemplate.execute(sql);
        }
    }
}
