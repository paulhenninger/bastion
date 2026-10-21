package dev.bastion.passkey;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import dev.bastion.audit.SecurityEventType;
import dev.bastion.audit.SecurityEvents;
import dev.bastion.common.ApiException;
import dev.bastion.config.AppProperties;
import dev.bastion.email.EmailService;
import dev.bastion.passkey.PasskeyChallenge.Purpose;
import dev.bastion.security.Tokens;
import dev.bastion.user.User;
import dev.bastion.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Passkeys (WebAuthn) on webauthn4j: registration while signed in, usernameless
 * sign-in, and re-authentication.
 *
 * <p>A passkey is the strongest credential the app issues: it is phishing-resistant
 * (the browser binds every signature to this site's origin, so a look-alike domain gets
 * nothing usable) and it combines possession with a biometric or PIN. So:
 * <ul>
 *   <li><b>User verification is required</b>, at registration and at every use — a mere
 *       touch is not enough for a credential that stands in for password and second
 *       factor together. That's what makes a passkey sign-in a "strong" session.</li>
 *   <li><b>Adding one requires a fresh re-authentication</b> (enforced by the controller):
 *       a borrowed session must not be able to plant a permanent way back in.</li>
 *   <li><b>Every challenge is single-use</b>, purpose-bound and user-bound where a user is
 *       known, and expires in five minutes.</li>
 *   <li><b>Signature counters are checked</b>: an authenticator that reports a counter at
 *       or below the stored one may have been cloned, and the sign-in is refused.</li>
 *   <li>Attestation is not requested ({@code "none"}): consumer passkeys rarely attest,
 *       and demanding it would exclude most of them for little gain.</li>
 * </ul>
 */
@Service
public class PasskeyService {

    private static final Logger log = LoggerFactory.getLogger(PasskeyService.class);
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final int MAX_PER_USER = 20;
    private static final long TIMEOUT_MS = 300_000;
    private static final String FAILED = "Passkey sign-in could not be verified";
    private static final String CHALLENGE = "challenge";
    private static final String REQUIRED = "required";

    /** ES256, EdDSA, RS256 — the set every platform authenticator covers. */
    private static final List<PublicKeyCredentialParameters> ALGORITHMS = List.of(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));

    private final PasskeyCredentialRepository credentials;
    private final PasskeyChallengeRepository challenges;
    private final UserRepository users;
    private final SecurityEvents events;
    private final EmailService email;
    private final String appName;
    private final String rpId;
    private final Set<Origin> origins;

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final WebAuthnManager webAuthn = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    private final AttestedCredentialDataConverter credentialDataConverter =
            new AttestedCredentialDataConverter(objectConverter);
    private final JsonMapper json = JsonMapper.builder().build();

    public PasskeyService(PasskeyCredentialRepository credentials, PasskeyChallengeRepository challenges,
                          UserRepository users, SecurityEvents events, EmailService email, AppProperties props) {
        this.credentials = credentials;
        this.challenges = challenges;
        this.users = users;
        this.events = events;
        this.email = email;
        this.appName = props.name();
        this.rpId = props.rpId();
        Set<Origin> allowed = new LinkedHashSet<>();
        allowed.add(Origin.create(originOf(props.baseUrl())));
        props.passkeys().extraOrigins().stream()
                .filter(o -> !o.isBlank())
                .forEach(o -> allowed.add(Origin.create(originOf(o.trim()))));
        this.origins = Set.copyOf(allowed);
    }

    // ------------------------------------------------------------ registration

    /** Options for {@code navigator.credentials.create()}. The caller has re-authenticated. */
    @Transactional
    public Map<String, Object> registrationOptions(Long userId) {
        User user = users.findByIdForUpdate(userId).orElseThrow();
        if (credentials.countByUserId(userId) >= MAX_PER_USER) {
            throw ApiException.badRequest("You've reached the maximum of " + MAX_PER_USER + " passkeys");
        }
        if (user.getWebauthnUserHandle() == null) {
            // Random, so the handle stored on the authenticator says nothing about the account.
            user.setWebauthnUserHandle(Tokens.randomBase64Url(32));
        }
        String challenge = newChallenge(Purpose.REGISTRATION, user);

        Map<String, Object> options = new LinkedHashMap<>();
        options.put(CHALLENGE, challenge);
        options.put("rp", Map.of("id", rpId, "name", appName));
        options.put("user", Map.of(
                "id", user.getWebauthnUserHandle(),
                "name", user.getEmail(),
                "displayName", user.getName() == null ? user.getEmail() : user.getName()));
        options.put("pubKeyCredParams", ALGORITHMS.stream()
                .map(p -> Map.of("type", "public-key", "alg", p.getAlg().getValue())).toList());
        options.put("timeout", TIMEOUT_MS);
        options.put("attestation", "none");
        // Stops the same authenticator being registered twice.
        options.put("excludeCredentials", credentials.findByUserIdOrderByCreatedAtAsc(userId).stream()
                .map(PasskeyService::descriptor).toList());
        options.put("authenticatorSelection", Map.of(
                "residentKey", REQUIRED,
                "requireResidentKey", true,
                "userVerification", REQUIRED));
        return options;
    }

    @Transactional
    public PasskeyCredential register(Long userId, String attestationObject, String clientDataJson,
                                      List<String> transports, String label) {
        PasskeyChallenge ch = consumeChallenge(clientDataJson, Purpose.REGISTRATION);
        if (ch.getUser() == null || !ch.getUser().getId().equals(userId)) {
            throw ApiException.badRequest("This passkey request has expired. Please try again.");
        }
        Set<String> transportSet = transports == null ? Set.of()
                : transports.stream().filter(t -> t != null && t.length() <= 32).limit(8).collect(Collectors.toSet());

        RegistrationData data;
        try {
            data = webAuthn.verify(
                    new RegistrationRequest(decode(attestationObject), decode(clientDataJson), transportSet),
                    new RegistrationParameters(serverProperty(ch.getChallenge()), ALGORITHMS, true, true));
        } catch (Exception e) {
            log.info("Passkey registration rejected for user {}: {}", userId, e.toString());
            throw ApiException.badRequest("The passkey couldn't be verified. Please try again.");
        }

        var attestation = data.getAttestationObject();
        AuthenticatorData<?> authData = attestation == null ? null : attestation.getAuthenticatorData();
        AttestedCredentialData acd = authData == null ? null : authData.getAttestedCredentialData();
        if (acd == null) {
            throw ApiException.badRequest("The passkey couldn't be verified. Please try again.");
        }
        String credentialId = encode(acd.getCredentialId());
        String idHash = Tokens.sha256(credentialId);
        if (credentials.existsByCredentialIdHash(idHash)) {
            throw new ApiException(HttpStatus.CONFLICT, "This passkey is already registered");
        }
        User user = users.getReferenceById(userId);
        PasskeyCredential credential = new PasskeyCredential();
        credential.setUser(user);
        credential.setCredentialId(credentialId);
        credential.setCredentialIdHash(idHash);
        credential.setAttestedCredentialData(credentialDataConverter.convert(acd));
        credential.setSignCount(authData.getSignCount());
        credential.setUvInitialized(authData.isFlagUV());
        credential.setBackupEligible(authData.isFlagBE());
        credential.setBackedUp(authData.isFlagBS());
        credential.setTransports(transportSet.isEmpty() ? null : String.join(",", transportSet));
        credential.setAaguid(acd.getAaguid().toString());
        credential.setLabel(cleanLabel(label));
        credentials.save(credential);

        User owner = users.findById(userId).orElseThrow();
        events.add(SecurityEventType.PASSKEY_ADDED, owner, credential.getLabel());
        email.sendSecurityNotice(owner.getEmail(), "A passkey was added",
                "A passkey (\"" + credential.getLabel() + "\") was added to your account. It can sign in "
                        + "without your password.");
        return credential;
    }

    @Transactional(readOnly = true)
    public List<PasskeyCredential> list(Long userId) {
        return credentials.findByUserIdOrderByCreatedAtAsc(userId);
    }

    @Transactional
    public PasskeyCredential rename(Long userId, Long id, String label) {
        PasskeyCredential credential = credentials.findByIdAndUserId(id, userId)
                .orElseThrow(() -> ApiException.notFound("Passkey not found"));
        credential.setLabel(cleanLabel(label));
        return credential;
    }

    @Transactional
    public void delete(Long userId, Long id) {
        PasskeyCredential credential = credentials.findByIdAndUserId(id, userId)
                .orElseThrow(() -> ApiException.notFound("Passkey not found"));
        credentials.delete(credential);
        User owner = users.findById(userId).orElseThrow();
        events.add(SecurityEventType.PASSKEY_REMOVED, owner, credential.getLabel());
        email.sendSecurityNotice(owner.getEmail(), "A passkey was removed",
                "The passkey \"" + credential.getLabel() + "\" was removed from your account.");
    }

    // ---------------------------------------------------------- authentication

    /** Options for {@code navigator.credentials.get()}: usernameless, so no credential list. */
    @Transactional
    public Map<String, Object> authenticationOptions() {
        return requestOptions(newChallenge(Purpose.AUTHENTICATION, null), List.of());
    }

    /**
     * Verifies an anonymous assertion and returns the account it signs in. One generic
     * failure for every reason, so responses can't probe which credentials exist.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public User authenticate(Assertion assertion) {
        PasskeyChallenge ch = consumeChallenge(assertion.clientDataJson(), Purpose.AUTHENTICATION);
        PasskeyCredential credential = verifyAssertion(ch, assertion);
        User user = credential.getUser();
        if (!user.isEnabled() || user.isLocked()) {
            events.add(SecurityEventType.SIGN_IN_REFUSED, user, user.isLocked() ? "account locked" : "not verified");
            throw new ApiException(HttpStatus.UNAUTHORIZED, FAILED);
        }
        return user;
    }

    /** Options to re-authenticate with one of {@code userId}'s own passkeys. */
    @Transactional
    public Map<String, Object> reauthOptions(Long userId) {
        List<PasskeyCredential> own = credentials.findByUserIdOrderByCreatedAtAsc(userId);
        if (own.isEmpty()) {
            throw ApiException.badRequest("This account has no passkeys");
        }
        User user = users.getReferenceById(userId);
        return requestOptions(newChallenge(Purpose.REAUTH, user),
                own.stream().map(PasskeyService::descriptor).toList());
    }

    @Transactional(noRollbackFor = ApiException.class)
    public void reauthenticate(Long userId, Assertion assertion) {
        PasskeyChallenge ch = consumeChallenge(assertion.clientDataJson(), Purpose.REAUTH);
        if (ch.getUser() == null || !ch.getUser().getId().equals(userId)) {
            throw ApiException.badRequest(FAILED);
        }
        PasskeyCredential credential = verifyAssertion(ch, assertion);
        if (!credential.getUser().getId().equals(userId)) {
            throw ApiException.badRequest(FAILED);
        }
    }

    /** The browser's assertion, each binary field base64url. */
    public record Assertion(String credentialId, String clientDataJson, String authenticatorData,
                            String signature, String userHandle) {
    }

    private PasskeyCredential verifyAssertion(PasskeyChallenge ch, Assertion assertion) {
        PasskeyCredential credential = credentials.findByCredentialIdHash(Tokens.sha256(assertion.credentialId()))
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, FAILED));
        User user = credential.getUser();
        // The handle the authenticator stored must be this account's, when it reports one.
        if (assertion.userHandle() != null && !assertion.userHandle().isBlank()
                && !MessageDigest.isEqual(
                        assertion.userHandle().getBytes(StandardCharsets.US_ASCII),
                        String.valueOf(user.getWebauthnUserHandle()).getBytes(StandardCharsets.US_ASCII))) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, FAILED);
        }
        AuthenticationData data;
        try {
            CredentialRecordImpl stored = new CredentialRecordImpl(new NoneAttestationStatement(),
                    credential.isUvInitialized(), credential.isBackupEligible(), credential.isBackedUp(),
                    credential.getSignCount(),
                    credentialDataConverter.convert(credential.getAttestedCredentialData()),
                    null, null, null, transports(credential));
            data = webAuthn.verify(
                    new AuthenticationRequest(decode(assertion.credentialId()),
                            blankToNull(assertion.userHandle()) == null ? null : decode(assertion.userHandle()),
                            decode(assertion.authenticatorData()), decode(assertion.clientDataJson()),
                            decode(assertion.signature())),
                    new AuthenticationParameters(serverProperty(ch.getChallenge()), stored, null, true, true));
        } catch (Exception e) {
            log.info("Passkey assertion rejected for user {}: {}", user.getId(), e.toString());
            events.add(SecurityEventType.PASSKEY_SIGN_IN_FAILED, user, e.getClass().getSimpleName());
            throw new ApiException(HttpStatus.UNAUTHORIZED, FAILED);
        }
        AuthenticatorData<?> authData = data.getAuthenticatorData();
        if (authData == null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, FAILED);
        }
        credential.setSignCount(authData.getSignCount());
        credential.setBackedUp(authData.isFlagBS());
        credential.setUvInitialized(credential.isUvInitialized() || authData.isFlagUV());
        credential.setLastUsedAt(Instant.now());
        return credential;
    }

    @Transactional
    public int purgeExpiredChallenges() {
        return challenges.purgeExpired(Instant.now());
    }

    // ---------------------------------------------------------------- helpers

    private Map<String, Object> requestOptions(String challenge, List<Map<String, Object>> allow) {
        Map<String, Object> options = new LinkedHashMap<>();
        options.put(CHALLENGE, challenge);
        options.put("rpId", rpId);
        options.put("timeout", TIMEOUT_MS);
        options.put("userVerification", REQUIRED);
        options.put("allowCredentials", allow);
        return options;
    }

    private String newChallenge(Purpose purpose, User user) {
        String value = Tokens.randomBase64Url(32);
        challenges.save(new PasskeyChallenge(value, purpose, user, Instant.now().plus(CHALLENGE_TTL)));
        return value;
    }

    /**
     * The challenge is echoed inside clientDataJSON; read it to find our row, spend the
     * row atomically, then let webauthn4j re-verify the echo against what we issued.
     */
    private PasskeyChallenge consumeChallenge(String clientDataJson, Purpose purpose) {
        String value;
        try {
            JsonNode node = json.readTree(new String(decode(clientDataJson), StandardCharsets.UTF_8)).get(CHALLENGE);
            value = node == null ? null : node.asString();
        } catch (Exception _) {
            value = null;
        }
        PasskeyChallenge ch = value == null ? null : challenges.findByChallenge(value)
                .filter(c -> c.getPurpose() == purpose).orElse(null);
        if (ch == null || challenges.consume(ch.getId(), Instant.now()) != 1) {
            throw ApiException.badRequest("This passkey request has expired. Please try again.");
        }
        return ch;
    }

    private ServerProperty serverProperty(String challenge) {
        // No top-origin configured: ceremonies from inside a cross-origin iframe are refused.
        return ServerProperty.builder()
                .origins(origins)
                .rpId(rpId)
                .challenge(new DefaultChallenge(decode(challenge)))
                .build();
    }

    private static Map<String, Object> descriptor(PasskeyCredential c) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("type", "public-key");
        d.put("id", c.getCredentialId());
        if (c.getTransports() != null) {
            d.put("transports", List.of(c.getTransports().split(",")));
        }
        return d;
    }

    private static Set<AuthenticatorTransport> transports(PasskeyCredential c) {
        if (c.getTransports() == null) {
            return Set.of();
        }
        return java.util.Arrays.stream(c.getTransports().split(","))
                .map(AuthenticatorTransport::create).collect(Collectors.toSet());
    }

    private static String cleanLabel(String label) {
        String cleaned = label == null ? "" : label.replaceAll("\\p{Cntrl}", " ").strip();
        if (cleaned.isEmpty()) {
            return "Passkey";
        }
        return cleaned.length() > 100 ? cleaned.substring(0, 100) : cleaned;
    }

    private static String originOf(String url) {
        URI uri = URI.create(url);
        return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }

    private static byte[] decode(String base64url) {
        if (base64url == null) {
            throw ApiException.badRequest("Malformed passkey response");
        }
        try {
            return Base64.getUrlDecoder().decode(base64url);
        } catch (IllegalArgumentException _) {
            throw ApiException.badRequest("Malformed passkey response");
        }
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
