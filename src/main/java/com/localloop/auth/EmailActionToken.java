package com.localloop.auth;

import java.time.Duration;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import com.localloop.user.User;

@Entity
@Table(name = "email_action_tokens", uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "purpose"}))
class EmailActionToken {
    enum Purpose {
        ACTIVATE("/activate", Duration.ofHours(24)),
        RESET("/reset-password", Duration.ofMinutes(30));

        final String path;
        final Duration lifetime;

        Purpose(String path, Duration lifetime) {
            this.path = path;
            this.lifetime = lifetime;
        }
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private Purpose purpose;
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;
    @Column(nullable = false)
    private Instant expiresAt;
    private Instant consumedAt;
    @Column(nullable = false)
    private Instant createdAt;

    protected EmailActionToken() {}

    EmailActionToken(User user, Purpose purpose) {
        this.user = user;
        this.purpose = purpose;
    }

    void rotate(String hash, Instant now) {
        tokenHash = hash;
        createdAt = now;
        expiresAt = now.plus(purpose.lifetime);
        consumedAt = null;
    }

    boolean usable(Instant now) {
        return consumedAt == null && now.isBefore(expiresAt);
    }

    User user() { return user; }
}
