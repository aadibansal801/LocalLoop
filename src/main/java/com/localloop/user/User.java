package com.localloop.user;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "users")
public class User {
    public enum Role { USER, ADMIN }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, length = 254, unique = true)
    private String email;
    @Column(length = 100)
    private String displayName;
    @Column(length = 60)
    private String passwordHash;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Role role = Role.USER;
    private Instant emailVerifiedAt;
    @Column(nullable = false)
    private boolean disabled;
    @Column(nullable = false)
    private long authVersion;
    private Instant lastAuthEmailAt;
    @Column(nullable = false)
    private Instant createdAt;
    @Column(nullable = false)
    private Instant updatedAt;

    protected User() {}

    public User(String email, Instant now) {
        this.email = email;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public Long id() { return id; }
    public String email() { return email; }
    public String displayName() { return displayName; }
    public String passwordHash() { return passwordHash; }
    public Role role() { return role; }
    public boolean verified() { return emailVerifiedAt != null; }
    public boolean disabled() { return disabled; }
    public long authVersion() { return authVersion; }
    public Instant lastAuthEmailAt() { return lastAuthEmailAt; }

    public void recordAuthEmail(Instant now) {
        lastAuthEmailAt = now;
        updatedAt = now;
    }

    public void activate(String name, String hash, Instant now) {
        displayName = name;
        passwordHash = hash;
        emailVerifiedAt = now;
        updatedAt = now;
    }

    public void resetPassword(String hash, Instant now) {
        passwordHash = hash;
        authVersion++;
        updatedAt = now;
    }
}
