import { api, ApiUser, setAccessToken } from './client';

interface AuthResponse {
  accessToken: string;
  user: ApiUser;
}

interface MessageResponse {
  message: string;
}

export async function signup(email: string, password: string, name: string): Promise<string> {
  const res = await api<MessageResponse>('/auth/signup', {
    method: 'POST',
    body: JSON.stringify({ email, password, name: name || null }),
  });
  return res.message;
}

export async function login(email: string, password: string): Promise<ApiUser> {
  const res = await api<AuthResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  setAccessToken(res.accessToken);
  return res.user;
}

export async function verifyEmail(token: string): Promise<ApiUser> {
  const res = await api<AuthResponse>(`/auth/verify-email?token=${encodeURIComponent(token)}`);
  setAccessToken(res.accessToken);
  return res.user;
}

export async function resendVerification(email: string): Promise<string> {
  const res = await api<MessageResponse>('/auth/resend-verification', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
  return res.message;
}

export async function forgotPassword(email: string): Promise<string> {
  const res = await api<MessageResponse>('/auth/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ email }),
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

export async function logout(): Promise<void> {
  try {
    await api<MessageResponse>('/auth/logout', { method: 'POST' });
  } finally {
    setAccessToken(null);
  }
}
