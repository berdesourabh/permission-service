package com.db.permission.dto;

import java.util.List;

public record TableGrant(String host, String database, String table, List<String> privileges) {
}
