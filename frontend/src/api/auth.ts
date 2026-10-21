import { api, ApiUser, setAccessToken } from './client';
import { getAssertion, RequestOptionsJSON } from './webauthn';

interface AuthResponse {
  accessToken: string;
  user: ApiUser;
  passwordBreached?: boolean;
}

interface MfaChallenge {
  mfaRequired: true;
  mfaToken: string;
  passwordBreached?: boolean;
}

interface MessageResponse {
  message: string;
}

export interface PublicConfig {
  appName: string;
  signupsOpen: boolean;
  passwordMinLength: number;
  passwordMaxLength: number;
  turnstileSiteKey: string | null;
}

/** The outcome of a password sign-in: done, or a second factor is owed. */
export type LoginResult =
  | { kind: 'signedIn'; user: ApiUser; passwordBreached: boolean }
  | { kind: 'mfa'; mfaToken: string; passwordBreached: boolean };

function signedIn(res: AuthResponse): ApiUser {
  setAccessToken(res.accessToken);
  return res.user;
}

export function getConfig(): Promise<PublicConfig> {
  return api<PublicConfig>('/auth/config');
}

export async function signup(email: string, password: string, name: string, captchaToken: string | null) {
  const res = await api<MessageResponse>('/auth/signup', {
    method: 'POST',
    body: JSON.stringify({ email, password, name: name || null, captchaToken }),
  });
  return res.message;
}

export async function login(email: string, password: string): Promise<LoginResult> {
  const res = await api<AuthResponse | MfaChallenge>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  if ('mfaRequired' in res) {
    return { kind: 'mfa', mfaToken: res.mfaToken, passwordBreached: !!res.passwordBreached };
  }
  return { kind: 'signedIn', user: signedIn(res), passwordBreached: !!res.passwordBreached };
}

export async function completeMfa(mfaToken: string, code: string): Promise<ApiUser> {
  return signedIn(
    await api<AuthResponse>('/auth/mfa', { method: 'POST', body: JSON.stringify({ mfaToken, code }) }),
  );
}

export async function passkeyLogin(): Promise<ApiUser> {
  const options = await api<RequestOptionsJSON>('/auth/passkey/options', { method: 'POST' });
  const assertion = await getAssertion(options);
  return signedIn(
    await api<AuthResponse>('/auth/passkey/verify', { method: 'POST', body: JSON.stringify(assertion) }),
  );
}

export async function verifyEmail(token: string, password: string): Promise<ApiUser> {
  return signedIn(
    await api<AuthResponse>('/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify({ token, password }),
    }),
  );
}

export async function resendVerification(email: string, captchaToken: string | null): Promise<string> {
  const res = await api<MessageResponse>('/auth/resend-verification', {
    method: 'POST',
    body: JSON.stringify({ email, captchaToken }),
  });
  return res.message;
}

export async function forgotPassword(email: string, captchaToken: string | null): Promise<string> {
  const res = await api<MessageResponse>('/auth/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ email, captchaToken }),
  });
  return res.message;
}

export async function resetPassword(token: string, newPassword: string): Promise<string> {
  const res = await api<MessageResponse>('/auth/reset-password', {
    method: 'POST',
    body: JSON.stringify({ token, newPassword }),
  });
  return res.message;
}

export async function confirmEmailChange(token: string): Promise<string> {
  const res = await api<MessageResponse>('/auth/confirm-email-change', {
    method: 'POST',
    body: JSON.stringify({ token }),
  });
  return res.message;
}

export async function logout(): Promise<void> {
  try {
    await api<MessageResponse>('/auth/logout', { method: 'POST' });
  } finally {
    setAccessToken(null);
  }
}

/**
 * Emailed links carry their token in the URL fragment (#token=...), which browsers
 * never send to a server — so it can't leak into access logs or Referer headers.
 * Read it, then strip it from the address bar and history.
 */
export function takeTokenFromFragment(): string {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  const token = params.get('token') ?? '';
  if (token) {
    window.history.replaceState(null, '', window.location.pathname);
  }
  return token;
}
