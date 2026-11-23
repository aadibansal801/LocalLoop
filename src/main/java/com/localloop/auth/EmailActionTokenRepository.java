package com.localloop.auth;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.localloop.auth.EmailActionToken.Purpose;

interface EmailActionTokenRepository extends JpaRepository<EmailActionToken, Long> {
    Optional<EmailActionToken> findByUserIdAndPurpose(long userId, Purpose purpose);

    @Query("select t from EmailActionToken t join fetch t.user where t.tokenHash = :hash and t.purpose = :purpose")
    Optional<EmailActionToken> findWithUser(String hash, Purpose purpose);

    @Query("select t.user.id from EmailActionToken t where t.tokenHash = :hash and t.purpose = :purpose")
    Optional<Long> findUserId(String hash, Purpose purpose);

    @Modifying
    @Query("""
            update EmailActionToken t set t.consumedAt = :now
            where t.user.id = :userId and t.tokenHash = :hash and t.purpose = :purpose
            and t.consumedAt is null and t.expiresAt > :now
            """)
    int consume(long userId, String hash, Purpose purpose, Instant now);
}
