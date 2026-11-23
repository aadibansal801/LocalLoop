package com.localloop.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.mail.MailException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import com.localloop.auth.EmailActionToken.Purpose;
import com.localloop.user.User;
import com.localloop.user.UserRepository;

@Service
class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern LINK_TOKEN = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final Duration COOLDOWN = Duration.ofMinutes(1);

    private final UserRepository users;
    private final EmailActionTokenRepository tokens;
    private final PasswordEncoder passwords;
    private final EmailGateway mail;
    private final AuthSettings settings;
    private final Clock clock;
    private final TransactionTemplate issuance;

    AuthService(UserRepository users, EmailActionTokenRepository tokens, PasswordEncoder passwords,
                EmailGateway mail, AuthSettings settings, Clock clock, PlatformTransactionManager transactions) {
        this.users = users;
        this.tokens = tokens;
        this.passwords = passwords;
        this.mail = mail;
        this.settings = settings;
        this.clock = clock;
        this.issuance = new TransactionTemplate(transactions);
        issuance.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        issuance.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
    }

    void requestLink(String email, Purpose purpose) {
        if (email.isEmpty() || purpose == Purpose.ACTIVATE && !settings.allowedDomain.isEmpty()
                && !email.substring(email.lastIndexOf('@') + 1).equals(settings.allowedDomain)) {
            return;
        }
        String rawToken;
        try {
            rawToken = issuance.execute(status -> issue(email, purpose));
        } catch (DataIntegrityViolationException collision) {
            if (purpose != Purpose.ACTIVATE || users.findIdByEmail(email).isEmpty()) {
                throw collision;
            }
            rawToken = issuance.execute(status -> issue(email, purpose));
        }
        if (rawToken != null) {
            String link = settings.baseUrl.resolve(purpose.path + "?token=" + rawToken).toString();
            String title = purpose == Purpose.ACTIVATE ? "Activate your LocalLoop account" : "Reset your LocalLoop password";
            try {
                mail.send(email, title, title + "\n\n" + link
                        + "\n\nIf you did not request this link, you can ignore this message.");
                log.info("Authentication email sent ({})", purpose);
            } catch (MailException failure) {
                log.warn("Authentication email delivery failed ({})", purpose);
            }
        }
    }

    private String issue(String email, Purpose purpose) {
        User user = users.findIdByEmail(email).flatMap(users::lockById).orElse(null);
        if (user == null && purpose == Purpose.ACTIVATE) {
            user = users.save(new User(email, clock.instant()));
        }
        Instant now = clock.instant();
        if (!eligible(user, purpose) || user.lastAuthEmailAt() != null
                && now.isBefore(user.lastAuthEmailAt().plus(COOLDOWN))) {
            return null;
        }
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        EmailActionToken token = tokens.findByUserIdAndPurpose(user.id(), purpose).orElse(null);
        if (token == null) {
            token = new EmailActionToken(user, purpose);
        }
        token.rotate(hash(rawToken), now);
        tokens.save(token);
        user.recordAuthEmail(now);
        return rawToken;
    }

    boolean usable(String rawToken, Purpose purpose) {
        if (!validToken(rawToken)) {
            return false;
        }
        return tokens.findWithUser(hash(rawToken), purpose)
                .filter(token -> eligible(token.user(), purpose) && token.usable(clock.instant())).isPresent();
    }

    @Transactional
    boolean redeem(String rawToken, Purpose purpose, String name, String password) {
        if (!validToken(rawToken) || !AuthInput.newPassword(password)
                || purpose == Purpose.ACTIVATE && !AuthInput.displayName(name)) {
            return false;
        }
        String hash = hash(rawToken);
        User user = tokens.findUserId(hash, purpose).flatMap(users::lockById).orElse(null);
        Instant now = clock.instant();
        if (!eligible(user, purpose) || tokens.consume(user.id(), hash, purpose, now) != 1) {
            return false;
        }
        String encoded = passwords.encode(password);
        if (purpose == Purpose.ACTIVATE) {
            user.activate(name, encoded, now);
        } else {
            user.resetPassword(encoded, now);
        }
        return true;
    }

    private static boolean eligible(User user, Purpose purpose) {
        return user != null && !user.disabled()
                && (purpose == Purpose.ACTIVATE ? !user.verified() : user.verified() && user.passwordHash() != null);
    }

    private static boolean validToken(String rawToken) {
        return rawToken != null && LINK_TOKEN.matcher(rawToken).matches();
    }

    private static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.US_ASCII));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
