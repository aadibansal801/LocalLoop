package com.localloop.auth;

import java.net.URI;
import java.util.Locale;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

@Component
class AuthSettings {
    final URI baseUrl;
    final String allowedDomain;
    final String mailFrom;

    AuthSettings(Environment env) {
        boolean prod = env.acceptsProfiles(Profiles.of("prod"));
        baseUrl = URI.create(required(env, "app.base-url"));
        String scheme = baseUrl.getScheme();
        if (baseUrl.getHost() == null || baseUrl.getRawUserInfo() != null
                || baseUrl.getRawQuery() != null || baseUrl.getRawFragment() != null
                || !(baseUrl.getPath().isEmpty() || "/".equals(baseUrl.getPath()))
                || !("https".equals(scheme) || !prod && "http".equals(scheme))) {
            throw new IllegalStateException("APP_BASE_URL must be an HTTP(S) origin and use HTTPS in prod");
        }
        allowedDomain = env.getProperty("app.allowed-email-domain", "").strip().toLowerCase(Locale.ROOT);
        if (!allowedDomain.isEmpty() && !allowedDomain.matches("[a-z0-9]+(?:[.-][a-z0-9]+)*")) {
            throw new IllegalStateException("ALLOWED_EMAIL_DOMAIN must be an exact DNS domain");
        }
        mailFrom = required(env, "app.mail-from");
        if (prod) {
            for (String key : new String[] {"spring.datasource.url", "spring.datasource.username",
                    "spring.datasource.password", "spring.mail.host", "spring.mail.port",
                    "spring.mail.username", "spring.mail.password", "server.ssl.key-store",
                    "server.ssl.key-store-password"}) {
                required(env, key);
            }
            if (!env.getProperty("server.ssl.enabled", Boolean.class, false)
                    || !env.getProperty("server.servlet.session.cookie.secure", Boolean.class, false)
                    || !env.getProperty("spring.mail.properties.mail.smtp.starttls.required", Boolean.class, false)) {
                throw new IllegalStateException("prod requires HTTPS, secure session cookies and SMTP STARTTLS");
            }
        }
    }

    private static String required(Environment env, String key) {
        String value = env.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing configuration: " + key);
        }
        return value;
    }
}
