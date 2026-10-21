package dev.bastion.passkey;

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
 * A WebAuthn challenge: 32 random bytes the authenticator must sign, single-use, five
 * minutes. Tied to a purpose (and, except for anonymous sign-in, to a user) so a
 * challenge issued for one ceremony can't be spent on another.
 */
@Entity
@Table(name = "webauthn_challenges")
public class PasskeyChallenge {

    public enum Purpose { REGISTRATION, AUTHENTICATION, REAUTH }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String challenge;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Purpose purpose;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    private User user;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    protected PasskeyChallenge() {
    }

    PasskeyChallenge(String challenge, Purpose purpose, User user, Instant expiresAt) {
        this.challenge = challenge;
        this.purpose = purpose;
        this.user = user;
        this.expiresAt = expiresAt;
    }

    public Long getId() { return id; }
    public String getChallenge() { return challenge; }
    public Purpose getPurpose() { return purpose; }
    public User getUser() { return user; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getUsedAt() { return usedAt; }
}
