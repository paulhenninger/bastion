package dev.bastion;

import com.webauthn4j.data.AuthenticatorAssertionResponse;
import com.webauthn4j.data.AuthenticatorAttestationResponse;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.PublicKeyCredential;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.authenticator.webauthn.NoneAttestationAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import dev.bastion.support.IntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Real WebAuthn ceremonies against an emulated authenticator (webauthn4j-test): the
 * signatures, origins, challenges and counters are all checked for real.
 */
class PasskeyIntegrationTest extends IntegrationTest {

    private static final String EMAIL = "passkey.user@example.com";
    private static final Origin ORIGIN = new Origin("http://localhost:5173");

    private NoneAttestationAuthenticator authenticator;
    private ClientPlatform browser;

    @BeforeEach
    void newAuthenticator() {
        authenticator = new NoneAttestationAuthenticator();
        browser = new ClientPlatform(ORIGIN, new WebAuthnAuthenticatorAdaptor(authenticator));
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] unb64(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    /** What the SPA does: options → navigator.credentials.create() → POST the result. */
    private void registerPasskey(Session session) throws Exception {
        JsonNode o = body(mvc.perform(as(session, post("/api/v1/users/me/passkeys/options")))
                .andExpect(status().isOk()).andReturn());
        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(o.get("rp").get("id").asString(), o.get("rp").get("name").asString()),
                new PublicKeyCredentialUserEntity(unb64(o.get("user").get("id").asString()),
                        o.get("user").get("name").asString(), o.get("user").get("displayName").asString()),
                new DefaultChallenge(unb64(o.get("challenge").asString())),
                List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                300_000L, List.of(),
                new AuthenticatorSelectionCriteria(null, true, ResidentKeyRequirement.REQUIRED,
                        UserVerificationRequirement.REQUIRED),
                null, null);
        PublicKeyCredential<AuthenticatorAttestationResponse, ?> credential = browser.create(options);
        mvc.perform(as(session, postJson("/api/v1/users/me/passkeys", Map.of(
                        "attestationObject", b64(credential.getResponse().getAttestationObject()),
                        "clientDataJSON", b64(credential.getResponse().getClientDataJSON()),
                        "transports", List.of("internal"),
                        "label", "Test laptop"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.label").value("Test laptop"));
    }

    /** options → navigator.credentials.get() → the assertion body the SPA posts. */
    private Map<String, Object> assertion(JsonNode o) {
        List<PublicKeyCredentialDescriptor> allow = new ArrayList<>();
        o.get("allowCredentials").forEach(c -> allow.add(new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY, unb64(c.get("id").asString()), null)));
        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions(
                new DefaultChallenge(unb64(o.get("challenge").asString())), 300_000L, o.get("rpId").asString(),
                allow, UserVerificationRequirement.REQUIRED, null);
        PublicKeyCredential<AuthenticatorAssertionResponse, ?> credential = browser.get(options);
        Map<String, Object> body = new HashMap<>();
        body.put("credentialId", b64(credential.getRawId()));
        body.put("clientDataJSON", b64(credential.getResponse().getClientDataJSON()));
        body.put("authenticatorData", b64(credential.getResponse().getAuthenticatorData()));
        body.put("signature", b64(credential.getResponse().getSignature()));
        if (credential.getResponse().getUserHandle() != null) {
            body.put("userHandle", b64(credential.getResponse().getUserHandle()));
        }
        return body;
    }

    private Map<String, Object> signInAssertion() throws Exception {
        return assertion(body(mvc.perform(post("/api/v1/auth/passkey/options")).andExpect(status().isOk()).andReturn()));
    }

    @Test
    void registeredPasskeySignsInWithoutAPasswordAsAStrongSession() throws Exception {
        Session session = newAccount(EMAIL);
        registerPasskey(session);

        Session passkeySession = session(mvc.perform(postJson("/api/v1/auth/passkey/verify", signInAssertion()))
                .andExpect(status().isOk()).andReturn());
        mvc.perform(as(passkeySession, get("/api/v1/users/me")))
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.strongSession").value(true));
        mvc.perform(as(passkeySession, get("/api/v1/users/me/passkeys")))
                .andExpect(jsonPath("$[0].lastUsedAt").isNotEmpty());
    }

    @Test
    void anAssertionCantBeReplayed() throws Exception {
        registerPasskey(newAccount(EMAIL));
        Map<String, Object> assertion = signInAssertion();
        mvc.perform(postJson("/api/v1/auth/passkey/verify", assertion)).andExpect(status().isOk());
        mvc.perform(postJson("/api/v1/auth/passkey/verify", assertion)).andExpect(status().isBadRequest());
    }

    @Test
    void aForeignOriginIsRefused() throws Exception {
        registerPasskey(newAccount(EMAIL));
        // A phishing site proxies the ceremony: the browser stamps the phisher's origin.
        browser.setOrigin(new Origin("https://bastion-login.example"));
        mvc.perform(postJson("/api/v1/auth/passkey/verify", signInAssertion())).andExpect(status().isUnauthorized());
    }

    @Test
    void aClonedAuthenticatorIsDetectedByItsCounter() throws Exception {
        registerPasskey(newAccount(EMAIL));
        mvc.perform(postJson("/api/v1/auth/passkey/verify", signInAssertion())).andExpect(status().isOk());
        mvc.perform(postJson("/api/v1/auth/passkey/verify", signInAssertion())).andExpect(status().isOk());
        // Pretend a copy of the key is in use: the stored counter is already ahead of it.
        jdbc.update("update webauthn_credentials set sign_count = 1000");
        mvc.perform(postJson("/api/v1/auth/passkey/verify", signInAssertion())).andExpect(status().isUnauthorized());
    }

    @Test
    void lockedAccountsCantSignInWithAPasskey() throws Exception {
        registerPasskey(newAccount(EMAIL));
        jdbc.update("update users set locked = true");
        mvc.perform(postJson("/api/v1/auth/passkey/verify", signInAssertion())).andExpect(status().isUnauthorized());
    }

    @Test
    void addingAPasskeyRequiresRecentReauthenticationWhichAPasskeyCanProvide() throws Exception {
        Session session = newAccount(EMAIL);
        registerPasskey(session);
        expireReauth(session);
        mvc.perform(as(session, post("/api/v1/users/me/passkeys/options")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REAUTH_REQUIRED"));

        JsonNode options = body(mvc.perform(as(session, post("/api/v1/users/me/reauth/passkey/options")))
                .andExpect(status().isOk()).andReturn());
        mvc.perform(as(session, postJson("/api/v1/users/me/reauth/passkey", assertion(options))))
                .andExpect(status().isOk());
        mvc.perform(as(session, post("/api/v1/users/me/passkeys/options"))).andExpect(status().isOk());
    }

    @Test
    void removingAPasskeyStopsItSigningIn() throws Exception {
        Session session = newAccount(EMAIL);
        registerPasskey(session);
        long id = body(mvc.perform(as(session, get("/api/v1/users/me/passkeys"))).andReturn()).get(0).get("id").asLong();
        mvc.perform(as(session, delete("/api/v1/users/me/passkeys/" + id))).andExpect(status().isNoContent());
        mvc.perform(postJson("/api/v1/auth/passkey/verify", signInAssertion())).andExpect(status().isUnauthorized());
    }

    @Test
    void onlyTheOwnerCanManageAPasskey() throws Exception {
        Session owner = newAccount(EMAIL);
        registerPasskey(owner);
        long id = body(mvc.perform(as(owner, get("/api/v1/users/me/passkeys"))).andReturn()).get(0).get("id").asLong();
        Session intruder = newAccount("intruder@example.com");
        mvc.perform(as(intruder, delete("/api/v1/users/me/passkeys/" + id))).andExpect(status().isNotFound());
    }
}
