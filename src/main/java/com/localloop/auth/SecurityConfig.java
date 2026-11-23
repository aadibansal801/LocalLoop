package com.localloop.auth;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.localloop.user.UserRepository;

import static com.localloop.auth.AuthRateLimit.Scope.LOGIN_EMAIL;
import static com.localloop.auth.AuthRateLimit.Scope.LOGIN_IP;

@Configuration(proxyBeanMethods = false)
class SecurityConfig {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, UserRepository users, AuthRateLimit rate,
                                           AuthInput input) throws Exception {
        var loginPost = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login");
        var logoutPost = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/logout");
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/register", "/activate", "/forgot-password",
                                "/reset-password", "/css/**", "/error").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .requestCache(cache -> cache.disable())
                .formLogin(form -> form.loginPage("/login")
                        .successHandler((request, response, authentication) -> {
                            log.info("Authentication succeeded");
                            response.sendRedirect(request.getContextPath() + "/dashboard");
                        })
                        .failureHandler((request, response, failure) -> loginFailure(request, response)))
                .logout(logout -> logout
                        .logoutRequestMatcher(request -> {
                            var authentication = SecurityContextHolder.getContext().getAuthentication();
                            return logoutPost.matches(request) && authentication != null
                                    && authentication.getPrincipal() instanceof AuthenticatedUser;
                        })
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessUrl("/login?logout"))
                .sessionManagement(session -> session.sessionFixation(fixation -> fixation.changeSessionId()))
                .headers(headers -> headers.referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER))
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")))
                .addFilterAfter(new AuthVersionFilter(users), HeaderWriterFilter.class)
                .addFilterBefore(new OncePerRequestFilter() {
                    @Override
                    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                                    FilterChain chain) throws ServletException, IOException {
                        if (loginPost.matches(request)) {
                            String email = input.email(request.getParameter("username"));
                            if (!rate.allow(LOGIN_IP, request.getRemoteAddr()) || email.isEmpty()
                                    || !rate.allow(LOGIN_EMAIL, email)
                                    || !AuthInput.loginPassword(request.getParameter("password"))) {
                                loginFailure(request, response);
                                return;
                            }
                        }
                        chain.doFilter(request, response);
                    }
                }, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    private static void loginFailure(HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.info("Authentication failed");
        response.sendRedirect(request.getContextPath() + "/login?error");
    }
}
