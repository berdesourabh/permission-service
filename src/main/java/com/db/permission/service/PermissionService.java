package com.db.permission.service;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.db.permission.config.PermissionServiceProperties;
import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.Privilege;
import com.db.permission.exception.DatabaseExceptionMapper;
import com.db.permission.exception.ErrorCode;
import com.db.permission.exception.PermissionException;
import com.db.permission.repository.PermissionRepository;
import com.db.permission.util.SqlValidator;

@Service
public class PermissionService {

    private static final Logger log = LoggerFactory.getLogger(PermissionService.class);

    private final PermissionRepository permissionRepository;
    private final List<String> protectedUsers;
    private final List<String> restrictedSchemas;

    public PermissionService(PermissionRepository permissionRepository, PermissionServiceProperties properties) {
        this.permissionRepository = permissionRepository;
        this.protectedUsers = properties.protectedUsers();
        this.restrictedSchemas = properties.restrictedSchemas();
    }

    public EnumSet<Privilege> grantPermission(PermissionChangeRequest request) {
        log.info("Granting permissions {} to user {} on {}.{}", request.permissions(), request.username(), request.database(), request.table());
        try {
            boolean isValidArguements = validate(request);
            checkNotProtected(request.username(), request.database());

            if (!isValidArguements) {
                throw new PermissionException(ErrorCode.INVALID_ARGUMENTS, "Invalid arguments provided. Please check the request parameters and try again.");
            }

            EnumSet<Privilege> privileges = getPrivileges(request.permissions());

            Set<String> tables = permissionRepository.getAllTablesInDatabase(request.database());
            if (tables.isEmpty() || !tables.contains(request.table())) {
                throw new PermissionException(ErrorCode.TABLE_NOT_FOUND, "Invalid database or table name provided. Please check and try again");
            }

            permissionRepository.grant(request.username(), validateDatabaseTableName(request.database()) ? request.database() : null,
                    validateDatabaseTableName(request.table()) ? request.table() : null,
                    privileges);
            return privileges;
        } catch (PermissionException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new PermissionException(ErrorCode.INVALID_ARGUMENTS, "Invalid arguments provided. Please check the request parameters and try again.");
        } catch (Exception e) {
            throw DatabaseExceptionMapper.map(e, request.username(), request.database(), request.table());
        }
    }

    public EnumSet<Privilege> revokePermission(PermissionChangeRequest request) {
        log.info("Revoking permissions {} from user {} on {}.{}", request.permissions(), request.username(), request.database(), request.table());
        try {
            boolean isValidArguements = validate(request);
            checkNotProtected(request.username(), request.database());

            if (!isValidArguements) {
                throw new PermissionException(ErrorCode.INVALID_ARGUMENTS, "Invalid arguments provided. Please check the request parameters and try again.");
            }

            EnumSet<Privilege> privileges = getPrivileges(request.permissions());

            Set<String> tables = permissionRepository.getAllTablesInDatabase(request.database());
            if (tables.isEmpty() || !tables.contains(request.table())) {
                throw new PermissionException(ErrorCode.TABLE_NOT_FOUND, "Invalid database or table name provided. Please check and try again");
            }

            permissionRepository.revoke(request.username(), validateDatabaseTableName(request.database()) ? request.database() : null,
                    validateDatabaseTableName(request.table()) ? request.table() : null,
                    privileges);
            return privileges;
        } catch (PermissionException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new PermissionException(ErrorCode.INVALID_ARGUMENTS, "Invalid arguments provided. Please check the request parameters and try again.");
        } catch (Exception e) {
            throw DatabaseExceptionMapper.map(e, request.username(), request.database(), request.table());
        }
    }

    public EnumSet<Privilege> getPrivileges(List<String> permissions) {
        if (permissions == null || permissions.isEmpty()) {
            return EnumSet.noneOf(Privilege.class);
        }
        EnumSet<Privilege> privileges = permissions.stream()
                .map(p -> Privilege.valueOf(p.toUpperCase()))
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(Privilege.class)));
        if (privileges.contains(Privilege.ALL)) {
            return EnumSet.of(Privilege.ALL);
        }
        return privileges;
    }

    private boolean validate(PermissionChangeRequest request) {
        return validateUsername(request.username())
                && validateDatabaseTableName(request.database())
                && validateDatabaseTableName(request.table())
                && !request.permissions().isEmpty()
                && request.permissions().stream().allMatch(p -> {
                    try {
                        Privilege.valueOf(p.toUpperCase());
                        return true;
                    } catch (IllegalArgumentException e) {
                        return false;
                    }
                });
    }

    private boolean validateDatabaseTableName(String name) {
        return SqlValidator.isValidDatabaseTableName(name);
    }

    private boolean validateUsername(String username) {
        return SqlValidator.isValidUsername(username);
    }

    private void checkNotProtected(String username, String database) {
        if (protectedUsers.contains(username)) {
            throw new PermissionException(ErrorCode.PROTECTED_ACCOUNT,
                    "User '" + username + "' is protected and cannot be changed through this service.");
        }
        if (restrictedSchemas.contains(database)) {
            throw new PermissionException(ErrorCode.SCHEMA_NOT_ALLOWED,
                    "Database '" + database + "' is a restricted schema and cannot be managed through this service.");
        }
    }

}
