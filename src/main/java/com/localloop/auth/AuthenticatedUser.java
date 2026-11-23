package com.localloop.auth;

import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.localloop.user.User;

final class AuthenticatedUser extends org.springframework.security.core.userdetails.User {
    private final long id;
    private final long authVersion;
    private final String displayName;
    private final User.Role role;

    AuthenticatedUser(User user) {
        super(user.email(), user.passwordHash() == null ? "" : user.passwordHash(),
                user.verified() && !user.disabled() && user.passwordHash() != null,
                true, true, true, List.of(new SimpleGrantedAuthority("ROLE_" + user.role())));
        id = user.id();
        authVersion = user.authVersion();
        displayName = user.displayName();
        role = user.role();
    }

    long id() { return id; }
    long authVersion() { return authVersion; }
    String displayName() { return displayName; }
    User.Role role() { return role; }
}
