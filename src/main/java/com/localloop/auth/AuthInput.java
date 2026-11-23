package com.localloop.auth;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import jakarta.validation.Validator;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.stereotype.Component;

@Component
class AuthInput {
    private record EmailAddress(@Email @Size(max = 254) @Pattern(regexp = "[!-~]+") String value) {}

    private final Validator validator;

    AuthInput(Validator validator) {
        this.validator = validator;
    }

    String email(String input) {
        if (input == null || input.length() > 512) {
            return "";
        }
        String normalized = input.strip().toLowerCase(Locale.ROOT);
        return validator.validate(new EmailAddress(normalized)).isEmpty() ? normalized : "";
    }

    static boolean loginPassword(String password) {
        return password != null && !password.isEmpty() && password.length() <= 72
                && password.indexOf(0) == -1 && utf8Bytes(password) <= 72;
    }

    static boolean newPassword(String password) {
        return loginPassword(password) && utf8Bytes(password) >= 12;
    }

    static boolean displayName(String name) {
        return name != null && !name.isBlank() && name.length() <= 100
                && name.codePoints().noneMatch(Character::isISOControl);
    }

    private static int utf8Bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }
}
