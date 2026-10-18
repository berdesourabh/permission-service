package com.db.permission.dto;

import java.util.List;

import com.db.permission.util.SqlValidator;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record PermissionChangeRequest(
        @NotNull
        @Pattern(regexp = SqlValidator.USERNAME_PATTERN, message = "must be a valid username")
        String username,
        @NotNull
        @Pattern(regexp = SqlValidator.DATABASE_TABLE_PATTERN, message = "must be a valid database name")
        String database,
        @NotNull
        @Pattern(regexp = SqlValidator.DATABASE_TABLE_PATTERN, message = "must be a valid table name")
        String table,
        @NotEmpty
        List<@NotNull @Pattern(regexp = "(?i)SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|ALL", message = "must be one of: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, ALL") String> permissions
        ) {

}
