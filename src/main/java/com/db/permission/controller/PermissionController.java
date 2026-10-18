package com.db.permission.controller;

import java.util.EnumSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.PermissionReponse;
import com.db.permission.dto.Privilege;
import com.db.permission.service.PermissionService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/permissions")
public class PermissionController {

    private final Logger log = LoggerFactory.getLogger(PermissionController.class);

    private final PermissionService permissionService;

    public PermissionController(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    @PostMapping("/grant")
    public ResponseEntity<PermissionReponse> grantPermission(@Valid @RequestBody PermissionChangeRequest request) {
        log.info("Received request to grant permissions: {}", request);
        EnumSet<Privilege> privileges = permissionService.grantPermission(request);
        List<String> privilegeNames = privileges.stream().map(Privilege::name).toList();
        PermissionReponse response = new PermissionReponse("Permissions granted successfully",
                request.username(),
                request.database(),
                request.table(),
                privilegeNames);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/revoke")
    public ResponseEntity<PermissionReponse> revokePermission(@Valid @RequestBody PermissionChangeRequest request) {
        log.info("Received request to revoke permissions: {}", request);
        EnumSet<Privilege> privileges = permissionService.revokePermission(request);
        List<String> privilegeNames = privileges.stream().map(Privilege::name).toList();
        PermissionReponse response = new PermissionReponse("Permissions revoked successfully",
                request.username(),
                request.database(),
                request.table(),
                privilegeNames);
        return ResponseEntity.ok(response);

    }
}
