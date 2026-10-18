package com.db.permission.service;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.verify;
import org.mockito.junit.jupiter.MockitoExtension;

import com.db.permission.repository.PermissionRepository;

@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    @Mock
    private PermissionRepository permissionRepository;

    @InjectMocks
    private PermissionService permissionService;

    @Test
    void grantPermissionDelegatesToRepository() {
        List<String> permissions = List.of("SELECT", "INSERT");

        permissionService.grantPermission("sourabh", "shop", "orders", permissions);

        verify(permissionRepository).grant("sourabh", "shop", "orders", permissions);
    }
}
