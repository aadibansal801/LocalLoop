package com.localloop.auth;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import com.localloop.user.UserRepository;

final class AuthVersionFilter extends OncePerRequestFilter {
    private final UserRepository users;
    private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

    AuthVersionFilter(UserRepository users) {
        this.users = users;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof AuthenticatedUser user
                && !users.existsByIdAndAuthVersionAndDisabledFalse(user.id(), user.authVersion())) {
            logout.logout(request, response, authentication);
        }
        chain.doFilter(request, response);
    }
}
