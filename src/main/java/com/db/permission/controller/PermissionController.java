package com.db.permission.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.db.permission.dto.PermissionChangeRequest;
import com.db.permission.dto.PermissionReponse;
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
        permissionService.grantPermission(request.username(), request.database(), request.table(), request.permissions());
        PermissionReponse response = new PermissionReponse("Permissions granted successfully", request.username(), request.database(), request.table(), request.permissions());
        return ResponseEntity.ok(response);
    }

}
