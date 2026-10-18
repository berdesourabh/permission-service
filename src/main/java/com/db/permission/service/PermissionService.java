package com.db.permission.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.db.permission.repository.PermissionRepository;

@Service
public class PermissionService {

    private static final Logger log = LoggerFactory.getLogger(PermissionService.class);

    private final PermissionRepository permissionRepository;

    public PermissionService(PermissionRepository permissionRepository) {
        this.permissionRepository = permissionRepository;
    }

    public void grantPermission(String username, String database, String table, List<String> permissions) {
        log.info("Granting permissions {} to user {} on {}.{}", permissions, username, database, table);
        permissionRepository.grant(username, database, table, permissions);
    }

}
