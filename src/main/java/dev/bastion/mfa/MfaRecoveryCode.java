package dev.bastion.mfa;

import dev.bastion.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
 * A single-use backup code for when the authenticator is lost. Stored as SHA-256:
 * each code carries ~50 bits from a 31-symbol alphabet and is attempt-limited per
 * account, so a fast hash is adequate and lookups stay indexed.
 */
@Entity
@Table(name = "mfa_recovery_codes")
public class MfaRecoveryCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    private User user;

    @Column(name = "code_hash", nullable = false, length = 64)
    private String codeHash;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    protected MfaRecoveryCode() {
    }

    MfaRecoveryCode(User user, String codeHash) {
        this.user = user;
        this.codeHash = codeHash;
    }

    public Long getId() { return id; }
    public User getUser() { return user; }
    public String getCodeHash() { return codeHash; }
    public Instant getUsedAt() { return usedAt; }
    public Instant getCreatedAt() { return createdAt; }
}
