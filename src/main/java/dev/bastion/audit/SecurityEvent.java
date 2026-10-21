package dev.bastion.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * One line of the security log. Written once, never updated. {@code userId} has no
 * foreign key on purpose: the record of what happened to an account must outlive it.
 */
@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 40)
    private SecurityEventType type;

    /** The account it happened to, when there is one. */
    @Column(name = "user_id")
    private Long userId;

    /** The address involved — for a failed sign-in, whatever was typed. */
    @Column(name = "subject_email", length = 255)
    private String subjectEmail;

    /** Who did it, when that isn't the account's owner (an administrator). */
    @Column(name = "actor_user_id")
    private Long actorUserId;

    @Column(length = 45)
    private String ip;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(length = 255)
    private String detail;

    protected SecurityEvent() {
    }

    // One argument per column of an immutable row; a builder would add nothing.
    @SuppressWarnings("java:S107")
    SecurityEvent(Instant occurredAt, SecurityEventType type, Long userId, String subjectEmail,
                  Long actorUserId, String ip, String userAgent, String detail) {
        this.occurredAt = occurredAt;
        this.type = type;
        this.userId = userId;
        this.subjectEmail = subjectEmail;
        this.actorUserId = actorUserId;
        this.ip = ip;
        this.userAgent = userAgent;
        this.detail = detail;
    }

    public Long getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public SecurityEventType getType() { return type; }
    public Long getUserId() { return userId; }
    public String getSubjectEmail() { return subjectEmail; }
    public Long getActorUserId() { return actorUserId; }
    public String getIp() { return ip; }
    public String getUserAgent() { return userAgent; }
    public String getDetail() { return detail; }
}
