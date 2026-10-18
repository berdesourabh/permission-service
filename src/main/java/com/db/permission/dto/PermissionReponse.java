package com.db.permission.dto;

import java.util.List;

public record PermissionReponse(String message, String username, String database, String table, List<String> permissions) {

}
