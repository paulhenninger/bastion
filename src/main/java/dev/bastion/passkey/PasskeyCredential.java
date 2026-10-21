package dev.bastion.passkey;

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
 * A registered passkey: the authenticator's public key and its metadata. Nothing here
 * is secret — the private key never leaves the user's device — so a database leak
 * yields nothing that can sign in.
 */
@Entity
@Table(name = "webauthn_credentials")
public class PasskeyCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    private User user;

    /** base64url credential id, as browsers present it. */
    @Column(name = "credential_id", nullable = false, length = 1400)
    private String credentialId;

    /** SHA-256 of the credential id: the unique, indexed lookup key. */
    @Column(name = "credential_id_hash", nullable = false, unique = true, length = 64)
    private String credentialIdHash;

    /** CBOR attested credential data (AAGUID, id, COSE public key), as webauthn4j encodes it. */
    @Column(name = "attested_credential_data", nullable = false, length = 4096)
    private byte[] attestedCredentialData;

    @Column(name = "sign_count", nullable = false)
    private long signCount;

    @Column(name = "uv_initialized", nullable = false)
    private boolean uvInitialized;

    @Column(name = "backup_eligible", nullable = false)
    private boolean backupEligible;

    @Column(name = "backed_up", nullable = false)
    private boolean backedUp;

    /** Comma-separated transport hints (internal, hybrid, usb, ...). */
    @Column(length = 255)
    private String transports;

    @Column(length = 36)
    private String aaguid;

    @Column(nullable = false, length = 100)
    private String label;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    public Long getId() { return id; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }
    public String getCredentialIdHash() { return credentialIdHash; }
    public void setCredentialIdHash(String credentialIdHash) { this.credentialIdHash = credentialIdHash; }
    public byte[] getAttestedCredentialData() { return attestedCredentialData; }
    public void setAttestedCredentialData(byte[] data) { this.attestedCredentialData = data; }
    public long getSignCount() { return signCount; }
    public void setSignCount(long signCount) { this.signCount = signCount; }
    public boolean isUvInitialized() { return uvInitialized; }
    public void setUvInitialized(boolean uvInitialized) { this.uvInitialized = uvInitialized; }
    public boolean isBackupEligible() { return backupEligible; }
    public void setBackupEligible(boolean backupEligible) { this.backupEligible = backupEligible; }
    public boolean isBackedUp() { return backedUp; }
    public void setBackedUp(boolean backedUp) { this.backedUp = backedUp; }
    public String getTransports() { return transports; }
    public void setTransports(String transports) { this.transports = transports; }
    public String getAaguid() { return aaguid; }
    public void setAaguid(String aaguid) { this.aaguid = aaguid; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(Instant lastUsedAt) { this.lastUsedAt = lastUsedAt; }
}
