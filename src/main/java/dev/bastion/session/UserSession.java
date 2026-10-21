package dev.bastion.session;

import dev.bastion.user.User;
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
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.Instant;

/**
 * One sign-in on one device. Refresh tokens rotate underneath it; every access
 * token carries its {@link #publicId}, and the auth filter checks the row on each
 * request — so revoking a session (sign-out, "sign out other devices", password
 * reset, admin lock) takes effect on the next request, not when a JWT expires.
 */
@Entity
@Table(name = "user_sessions")
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Random, unguessable id exposed to clients (the JWT {@code sid}, the sessions list). */
    @Column(name = "public_id", nullable = false, unique = true, length = 43)
    private String publicId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_method", nullable = false, length = 20)
    private AuthMethod authMethod;

    /** Two factors were proven for this session (at sign-in or by enrolling one in it). */
    @Column(name = "strong_auth", nullable = false)
    private boolean strongAuth;

    @Column(length = 45)
    private String ip;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    /** Absolute end — refreshing never extends past it. */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /** Last successful re-authentication ("sudo mode") in this session. */
    @Column(name = "reauth_at")
    private Instant reauthAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    public boolean isActive(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now);
    }

    public Long getId() { return id; }
    public String getPublicId() { return publicId; }
    public void setPublicId(String publicId) { this.publicId = publicId; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public AuthMethod getAuthMethod() { return authMethod; }
    public void setAuthMethod(AuthMethod authMethod) { this.authMethod = authMethod; }
    public boolean isStrongAuth() { return strongAuth; }
    public void setStrongAuth(boolean strongAuth) { this.strongAuth = strongAuth; }
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant lastSeenAt) { this.lastSeenAt = lastSeenAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public Instant getReauthAt() { return reauthAt; }
    public void setReauthAt(Instant reauthAt) { this.reauthAt = reauthAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
}
