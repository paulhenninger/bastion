package dev.bastion.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    /** Argon2id (or legacy BCrypt, upgraded on next sign-in), prefixed with its algorithm id. */
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(length = 100)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role = Role.USER;

    /** False until the email address is verified. Unverified accounts cannot log in. */
    @Column(nullable = false)
    private boolean enabled = false;

    /**
     * Admin-imposed login block. Deliberately distinct from {@link #enabled}: reusing the
     * verification flag would let a locked-but-verified user unlock themselves through
     * the resend-verification flow.
     */
    @Column(nullable = false)
    private boolean locked = false;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "password_changed_at")
    private Instant passwordChangedAt;

    /** AES-GCM ciphertext of the TOTP shared secret (see DataCipher); null when TOTP is off. */
    @Column(name = "totp_secret", length = 255)
    private String totpSecret;

    /** Encrypted secret generated at setup, promoted to {@link #totpSecret} once a code proves it. */
    @Column(name = "totp_pending_secret", length = 255)
    private String totpPendingSecret;

    /** Last accepted TOTP time step — a code can be used exactly once (RFC 6238 §5.2). */
    @Column(name = "totp_last_step")
    private Long totpLastStep;

    /** Random WebAuthn user handle: stable per account, never the email or database id. */
    @Column(name = "webauthn_user_handle", length = 64, unique = true)
    private String webauthnUserHandle;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
        updatedAt = createdAt;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    public boolean isTotpEnabled() {
        return totpSecret != null;
    }

    public Long getId() { return id; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isLocked() { return locked; }
    public void setLocked(boolean locked) { this.locked = locked; }
    public Instant getLastLoginAt() { return lastLoginAt; }
    public void setLastLoginAt(Instant lastLoginAt) { this.lastLoginAt = lastLoginAt; }
    public Instant getPasswordChangedAt() { return passwordChangedAt; }
    public void setPasswordChangedAt(Instant passwordChangedAt) { this.passwordChangedAt = passwordChangedAt; }
    public String getTotpSecret() { return totpSecret; }
    public void setTotpSecret(String totpSecret) { this.totpSecret = totpSecret; }
    public String getTotpPendingSecret() { return totpPendingSecret; }
    public void setTotpPendingSecret(String totpPendingSecret) { this.totpPendingSecret = totpPendingSecret; }
    public Long getTotpLastStep() { return totpLastStep; }
    public void setTotpLastStep(Long totpLastStep) { this.totpLastStep = totpLastStep; }
    public String getWebauthnUserHandle() { return webauthnUserHandle; }
    public void setWebauthnUserHandle(String webauthnUserHandle) { this.webauthnUserHandle = webauthnUserHandle; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
