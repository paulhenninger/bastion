package dev.bastion.session;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * Row-locked: two requests presenting the same token serialise here, so exactly
     * one rotates it and the other sees it consumed. Without the lock both read
     * "not yet revoked", both mint a replacement, and one stolen token becomes two
     * live sessions — the very thing rotation exists to prevent.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from RefreshToken t join fetch t.session s join fetch t.user where t.tokenHash = :hash")
    Optional<RefreshToken> findForRotation(@Param("hash") String hash);

    @Query("select t from RefreshToken t join fetch t.session join fetch t.user where t.tokenHash = :hash")
    Optional<RefreshToken> findByTokenHash(@Param("hash") String hash);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update RefreshToken t set t.revokedAt = :now where t.session.id = :sessionId and t.revokedAt is null")
    int revokeAllForSession(@Param("sessionId") Long sessionId, @Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update RefreshToken t set t.revokedAt = :now where t.user.id = :userId and t.revokedAt is null")
    int revokeAllForUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update RefreshToken t set t.revokedAt = :now where t.user.id = :userId "
            + "and t.session.id <> :keepSessionId and t.revokedAt is null")
    int revokeAllForUserExceptSession(@Param("userId") Long userId, @Param("keepSessionId") Long keepSessionId,
                                      @Param("now") Instant now);

    @Modifying
    @Query("delete from RefreshToken t where t.expiresAt < :cutoff or (t.revokedAt is not null and t.revokedAt < :cutoff)")
    int purgeOld(@Param("cutoff") Instant cutoff);
}

interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    /** The per-request check: the session and its user in one query. */
    @Query("select s from UserSession s join fetch s.user where s.publicId = :publicId")
    Optional<UserSession> findByPublicIdWithUser(@Param("publicId") String publicId);

    Optional<UserSession> findByPublicIdAndUserId(String publicId, Long userId);

    @Query("select s from UserSession s where s.user.id = :userId and s.revokedAt is null "
            + "and s.expiresAt > :now order by s.lastSeenAt desc")
    List<UserSession> findActive(@Param("userId") Long userId, @Param("now") Instant now);

    @Query("select count(s) > 0 from UserSession s where s.user.id = :userId and s.id <> :exceptId "
            + "and s.createdAt > :since and (s.ip = :ip or s.userAgent = :userAgent)")
    boolean seenBefore(@Param("userId") Long userId, @Param("exceptId") Long exceptId,
                       @Param("since") Instant since, @Param("ip") String ip,
                       @Param("userAgent") String userAgent);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update UserSession s set s.revokedAt = :now where s.user.id = :userId and s.revokedAt is null")
    int revokeAllForUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update UserSession s set s.revokedAt = :now where s.user.id = :userId and s.id <> :keepId "
            + "and s.revokedAt is null")
    int revokeOthers(@Param("userId") Long userId, @Param("keepId") Long keepId, @Param("now") Instant now);

    @Modifying
    @Query("delete from UserSession s where s.expiresAt < :cutoff or (s.revokedAt is not null and s.revokedAt < :cutoff)")
    int purgeOld(@Param("cutoff") Instant cutoff);
}
