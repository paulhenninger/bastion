package dev.bastion.user;

import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByWebauthnUserHandle(String handle);

    boolean existsByEmail(String email);

    long countByRole(Role role);

    /** For read-modify-write on security state (TOTP step, role) that must not interleave. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.id = :id")
    Optional<User> findByIdForUpdate(@Param("id") Long id);

    @Query("select u from User u where lower(u.email) like lower(concat('%', :q, '%')) "
            + "or lower(u.name) like lower(concat('%', :q, '%'))")
    Page<User> search(@Param("q") String query, Pageable pageable);

    @Modifying
    @Query("delete from User u where u.enabled = false and u.createdAt < :cutoff")
    int purgeUnverified(@Param("cutoff") Instant cutoff);
}
