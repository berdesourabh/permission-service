package com.db.permission.dto;

import java.util.List;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record PermissionChangeRequest(
        @NotNull
        String username,
        @NotNull
        String database,
        @NotNull
        String table,
        @NotEmpty
        List<@NotNull @Pattern(regexp = "(?i)SELECT|INSERT|UPDATE|DELETE|ALL", message = "must be one of: SELECT, INSERT, UPDATE, DELETE, ALL") String> permissions
        ) {

}
