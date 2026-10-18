package com.db.permission.util;

public final class SqlValidator {

    public static final String DATABASE_TABLE_PATTERN = "[A-Za-z0-9_$-]{1,64}";
    public static final String USERNAME_PATTERN = "[A-Za-z0-9_.-]{1,80}";

    public static boolean isValidDatabaseTableName(String name) {
        return name != null && name.matches(DATABASE_TABLE_PATTERN);
    }

    public static boolean isValidUsername(String username) {
        return username != null && username.matches(USERNAME_PATTERN);
    }

}
