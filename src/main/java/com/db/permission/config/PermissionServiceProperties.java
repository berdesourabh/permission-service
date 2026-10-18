package com.db.permission.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "permission-service")
public record PermissionServiceProperties(
        @DefaultValue({"mysql", "information_schema", "performance_schema", "sys"})
        List<String> restrictedSchemas,
        @DefaultValue({"root", "mariadb.sys"})
        List<String> protectedUsers) {

}
