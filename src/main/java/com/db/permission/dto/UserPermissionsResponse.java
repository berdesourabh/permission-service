package com.db.permission.dto;

import java.util.List;

public record UserPermissionsResponse(String username, List<TableGrant> grants) {
}
