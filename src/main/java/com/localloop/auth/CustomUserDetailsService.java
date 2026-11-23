package com.localloop.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.localloop.user.UserRepository;

@Service
class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository users;
    private final AuthInput input;

    CustomUserDetailsService(UserRepository users, AuthInput input) {
        this.users = users;
        this.input = input;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        return users.findByEmail(input.email(username)).map(AuthenticatedUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));
    }
}
