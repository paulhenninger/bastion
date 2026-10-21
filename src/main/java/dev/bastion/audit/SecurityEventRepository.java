package dev.bastion.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    List<SecurityEvent> findTop50ByUserIdOrderByOccurredAtDescIdDesc(Long userId);

    List<SecurityEvent> findByUserIdOrderByOccurredAtDescIdDesc(Long userId);

    /** Admin search; every filter optional. */
    @Query("select e from SecurityEvent e where (:userId is null or e.userId = :userId) "
            + "and (:email is null or e.subjectEmail = :email) "
            + "and (:ip is null or e.ip = :ip) "
            + "and (:type is null or e.type = :type) "
            + "order by e.occurredAt desc, e.id desc")
    Page<SecurityEvent> search(@Param("userId") Long userId, @Param("email") String email,
                               @Param("ip") String ip, @Param("type") SecurityEventType type,
                               Pageable pageable);

    @Modifying
    @Query("delete from SecurityEvent e where e.occurredAt < :cutoff")
    int purgeOlderThan(@Param("cutoff") Instant cutoff);
}
