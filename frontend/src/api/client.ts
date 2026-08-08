// Fetch wrapper with in-memory access token and single-flight silent refresh.
//
// The access token lives in this module's memory only — never localStorage —
// so XSS can't exfiltrate a long-lived credential. The refresh token is an
// HttpOnly cookie the browser attaches to /api/v1/auth/* on its own.

const API_BASE = '/api/v1';

let accessToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;

export interface ApiUser {
  id: number;
  email: string;
  name: string | null;
  role: 'USER' | 'ADMIN';
}

export class ApiError extends Error {
  status: number;
  fields?: Record<string, string>;

  constructor(status: number, message: string, fields?: Record<string, string>) {
    super(message);
    this.status = status;
    this.fields = fields;
  }
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

/** One refresh at a time, however many 401s arrive together. */
export function refreshSession(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = doRefresh().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

async function doRefresh(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
    });
    if (!res.ok) {
      accessToken = null;
      return false;
    }
    const body = (await res.json()) as { accessToken: string };
    accessToken = body.accessToken;
    return true;
  } catch {
    accessToken = null;
    return false;
  }
}

async function rawRequest(path: string, options: RequestInit): Promise<Response> {
  const headers = new Headers(options.headers);
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  return fetch(`${API_BASE}${path}`, { ...options, headers, credentials: 'include' });
}

/** JSON request with one silent-refresh retry on 401. */
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  let res = await rawRequest(path, options);

  if (res.status === 401 && !path.startsWith('/auth/')) {
    const refreshed = await refreshSession();
    if (refreshed) {
      res = await rawRequest(path, options);
    }
  }

  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    let fields: Record<string, string> | undefined;
    try {
      const body = (await res.json()) as { message?: string; fields?: Record<string, string> };
      if (body.message) message = body.message;
      fields = body.fields;
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    throw new ApiError(res.status, message, fields);
  }

  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}
