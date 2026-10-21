// Passkey ceremonies. The server speaks base64url for every binary field; the
// browser's WebAuthn API speaks ArrayBuffers. These helpers translate both ways.
// (PublicKeyCredential.parse*OptionsFromJSON would do it natively, but isn't in
// every browser this app supports yet.)

function toBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function toBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface Descriptor {
  type: 'public-key';
  id: string;
  transports?: AuthenticatorTransport[];
}

export interface CreationOptionsJSON {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout: number;
  attestation: AttestationConveyancePreference;
  excludeCredentials: Descriptor[];
  authenticatorSelection: AuthenticatorSelectionCriteria;
}

export interface RequestOptionsJSON {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: UserVerificationRequirement;
  allowCredentials: Descriptor[];
}

export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window && !!navigator.credentials;
}

/** navigator.credentials.create(), returning the body POST /users/me/passkeys expects. */
export async function createPasskey(options: CreationOptionsJSON, label: string) {
  const credential = (await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: toBuffer(options.challenge),
      user: { ...options.user, id: toBuffer(options.user.id) },
      excludeCredentials: options.excludeCredentials.map((c) => ({ ...c, id: toBuffer(c.id) })),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new DOMException('No credential', 'NotAllowedError');
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    attestationObject: toBase64url(response.attestationObject),
    clientDataJSON: toBase64url(response.clientDataJSON),
    transports: response.getTransports ? response.getTransports() : [],
    label,
  };
}

/** navigator.credentials.get(), returning the assertion body the server verifies. */
export async function getAssertion(options: RequestOptionsJSON) {
  const credential = (await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: toBuffer(options.challenge),
      allowCredentials: options.allowCredentials.map((c) => ({ ...c, id: toBuffer(c.id) })),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new DOMException('No credential', 'NotAllowedError');
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    credentialId: toBase64url(credential.rawId),
    clientDataJSON: toBase64url(response.clientDataJSON),
    authenticatorData: toBase64url(response.authenticatorData),
    signature: toBase64url(response.signature),
    userHandle: response.userHandle ? toBase64url(response.userHandle) : null,
  };
}

/** A sensible default name for a new passkey, from the browser's platform. */
export function defaultPasskeyLabel(): string {
  const ua = navigator.userAgent;
  if (/iPhone|iPad/.test(ua)) return 'iPhone / iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Mac OS X/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows';
  if (/Linux/.test(ua)) return 'Linux';
  return 'Passkey';
}
