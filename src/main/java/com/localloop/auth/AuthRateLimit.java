package com.localloop.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

@Component
class AuthRateLimit {
    enum Scope {
        LOGIN_IP(20), LOGIN_EMAIL(5), MAIL_IP(10), MAIL_EMAIL(3), REDEEM_IP(15);

        final int limit;

        Scope(int limit) {
            this.limit = limit;
        }
    }

    private static final Duration WINDOW = Duration.ofMinutes(1);
    private static final int MAX_KEYS_PER_SCOPE = 2_000;

    private record Window(Instant expiresAt, int used) {}

    private final Clock clock;
    private final Map<Scope, Map<String, Window>> limits = new EnumMap<>(Scope.class);
    private Instant pruneAt = Instant.MIN;

    AuthRateLimit(Clock clock) {
        this.clock = clock;
        for (Scope scope : Scope.values()) {
            limits.put(scope, new HashMap<>());
        }
    }

    // shortcut: counters are shared within one process, use a shared limiter before scaling out.
    synchronized boolean allow(Scope scope, String key) {
        Instant now = clock.instant();
        if (!now.isBefore(pruneAt)) {
            limits.values().forEach(windows -> windows.values()
                    .removeIf(window -> !now.isBefore(window.expiresAt())));
            pruneAt = now.plus(WINDOW);
        }
        var windows = limits.get(scope);
        var window = windows.get(key);
        if (window == null && windows.size() >= MAX_KEYS_PER_SCOPE) {
            return false;
        }
        if (window == null || !now.isBefore(window.expiresAt())) {
            windows.put(key, new Window(now.plus(WINDOW), 1));
            return true;
        }
        if (window.used() >= scope.limit) {
            return false;
        }
        windows.put(key, new Window(window.expiresAt(), window.used() + 1));
        return true;
    }
}
