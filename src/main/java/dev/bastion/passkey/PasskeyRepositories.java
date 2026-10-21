package dev.bastion.passkey;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, Long> {

    @Query("select c from PasskeyCredential c join fetch c.user where c.credentialIdHash = :hash")
    Optional<PasskeyCredential> findByCredentialIdHash(@Param("hash") String hash);

    List<PasskeyCredential> findByUserIdOrderByCreatedAtAsc(Long userId);

    Optional<PasskeyCredential> findByIdAndUserId(Long id, Long userId);

    long countByUserId(Long userId);

    boolean existsByCredentialIdHash(String hash);
}

interface PasskeyChallengeRepository extends JpaRepository<PasskeyChallenge, Long> {

    @Query("select c from PasskeyChallenge c left join fetch c.user where c.challenge = :challenge")
    Optional<PasskeyChallenge> findByChallenge(@Param("challenge") String challenge);

    /** Spends a challenge if it is still live; the row count says whether this caller won. */
    @Modifying(flushAutomatically = true)
    @Query("update PasskeyChallenge c set c.usedAt = :now where c.id = :id and c.usedAt is null and c.expiresAt > :now")
    int consume(@Param("id") Long id, @Param("now") Instant now);

    @Modifying
    @Query("delete from PasskeyChallenge c where c.expiresAt < :cutoff")
    int purgeExpired(@Param("cutoff") Instant cutoff);
}
