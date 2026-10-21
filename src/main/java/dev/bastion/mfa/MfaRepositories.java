package dev.bastion.mfa;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

/*
 * Bulk updates here flush but deliberately do NOT clear the persistence context:
 * they run mid-transaction while the caller holds a locked challenge and user, and
 * clearing would detach those — silently dropping the "challenge used" and "TOTP
 * step consumed" writes that make codes single-use. None of these statements touch
 * an entity the callers hold, so there is no stale state to clear.
 */
interface MfaRecoveryCodeRepository extends JpaRepository<MfaRecoveryCode, Long> {

    /** Burns a code if — and only if — it is still unused; the row count says who won. */
    @Modifying(flushAutomatically = true)
    @Query("update MfaRecoveryCode c set c.usedAt = :now where c.user.id = :userId "
            + "and c.codeHash = :hash and c.usedAt is null")
    int consume(@Param("userId") Long userId, @Param("hash") String hash, @Param("now") Instant now);

    @Query("select count(c) from MfaRecoveryCode c where c.user.id = :userId and c.usedAt is null")
    long countUnused(@Param("userId") Long userId);

    @Modifying(flushAutomatically = true)
    @Query("delete from MfaRecoveryCode c where c.user.id = :userId")
    int deleteAllForUser(@Param("userId") Long userId);
}

interface MfaChallengeRepository extends JpaRepository<MfaChallenge, Long> {

    /** Row-locked so parallel guesses against one challenge are counted one at a time. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from MfaChallenge c join fetch c.user where c.tokenHash = :hash")
    Optional<MfaChallenge> findForVerification(@Param("hash") String hash);

    @Modifying(flushAutomatically = true)
    @Query("update MfaChallenge c set c.usedAt = :now where c.user.id = :userId and c.usedAt is null")
    int invalidateAllForUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying
    @Query("delete from MfaChallenge c where c.expiresAt < :cutoff")
    int purgeExpired(@Param("cutoff") Instant cutoff);
}
