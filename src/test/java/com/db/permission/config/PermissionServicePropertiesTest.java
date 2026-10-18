package com.db.permission.config;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

class PermissionServicePropertiesTest {

    @Test
    void bindsYamlLists() {
        // A YAML list such as ["billing", "audit"] reaches Spring as indexed keys.
        PermissionServiceProperties properties = bind(Map.of(
                "permission-service.restricted-schemas[0]", "billing",
                "permission-service.restricted-schemas[1]", "audit",
                "permission-service.protected-users[0]", "svc_admin"));

        assertThat(properties.restrictedSchemas()).containsExactly("billing", "audit");
        assertThat(properties.protectedUsers()).containsExactly("svc_admin");
    }

    @Test
    void bindsCommaSeparatedValues() {
        PermissionServiceProperties properties = bind(Map.of(
                "permission-service.restricted-schemas", "billing,audit",
                "permission-service.protected-users", "svc_admin,dba"));

        assertThat(properties.restrictedSchemas()).containsExactly("billing", "audit");
        assertThat(properties.protectedUsers()).containsExactly("svc_admin", "dba");
    }

    @Test
    void usesDefaultsWhenNotConfigured() {
        PermissionServiceProperties properties = bind(Map.of());

        assertThat(properties.restrictedSchemas())
                .containsExactly("mysql", "information_schema", "performance_schema", "sys");
        assertThat(properties.protectedUsers()).containsExactly("root", "mariadb.sys");
    }

    private static PermissionServiceProperties bind(Map<String, String> source) {
        return new Binder(new MapConfigurationPropertySource(source))
                .bindOrCreate("permission-service", PermissionServiceProperties.class);
    }
}
