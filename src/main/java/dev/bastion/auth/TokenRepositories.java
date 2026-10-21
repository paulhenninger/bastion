package dev.bastion.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/*
 * Single-use tokens are consumed with a conditional UPDATE ("... where used_at is
 * null") and the affected-row count decides who won. Read-check-write would let two
 * concurrent requests both see the token unused and both act on it.
 */

interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    @Query("select t from EmailVerificationToken t join fetch t.user where t.tokenHash = :hash")
    Optional<EmailVerificationToken> findByTokenHash(@Param("hash") String hash);

    /** Pending signup passwords for this account, newest first. */
    @Query("select t from EmailVerificationToken t where t.user.id = :userId and t.usedAt is null "
            + "and t.expiresAt > :now and t.passwordHash is not null order by t.createdAt desc, t.id desc")
    List<EmailVerificationToken> findPendingWithPassword(@Param("userId") Long userId, @Param("now") Instant now);

    @Query("select count(t) from EmailVerificationToken t where t.user.id = :userId and t.usedAt is null "
            + "and t.expiresAt > :now")
    long countPending(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update EmailVerificationToken t set t.usedAt = :now where t.user.id = :userId and t.usedAt is null")
    int consumeAllForUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying
    @Query("delete from EmailVerificationToken t where t.expiresAt < :cutoff")
    int purgeExpired(@Param("cutoff") Instant cutoff);
}

interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    @Query("select t from PasswordResetToken t join fetch t.user where t.tokenHash = :hash")
    Optional<PasswordResetToken> findByTokenHash(@Param("hash") String hash);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update PasswordResetToken t set t.usedAt = :now where t.id = :id and t.usedAt is null")
    int consume(@Param("id") Long id, @Param("now") Instant now);

    /** Any outstanding link dies when the password changes by any route. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update PasswordResetToken t set t.usedAt = :now where t.user.id = :userId and t.usedAt is null")
    int consumeAllForUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying
    @Query("delete from PasswordResetToken t where t.expiresAt < :cutoff")
    int purgeExpired(@Param("cutoff") Instant cutoff);
}

interface EmailChangeTokenRepository extends JpaRepository<EmailChangeToken, Long> {

    @Query("select t from EmailChangeToken t join fetch t.user where t.tokenHash = :hash")
    Optional<EmailChangeToken> findByTokenHash(@Param("hash") String hash);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update EmailChangeToken t set t.usedAt = :now where t.id = :id and t.usedAt is null")
    int consume(@Param("id") Long id, @Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update EmailChangeToken t set t.usedAt = :now where t.user.id = :userId and t.usedAt is null")
    int consumeAllForUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying
    @Query("delete from EmailChangeToken t where t.expiresAt < :cutoff")
    int purgeExpired(@Param("cutoff") Instant cutoff);
}
