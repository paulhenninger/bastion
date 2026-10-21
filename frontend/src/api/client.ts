// Fetch wrapper with an in-memory access token, single-flight silent refresh and
// step-up re-authentication.
//
// The access token lives in this module's memory only — never localStorage or
// sessionStorage — so XSS can't read a credential that outlives the page. The
// refresh token is an HttpOnly cookie the browser attaches to /api/v1/auth/* on
// its own; script never sees it.

const API_BASE = '/api/v1';

/**
 * Sent on every request. The server requires it on the cookie-authenticated
 * endpoints (refresh, logout): a cross-site page can't add a custom header
 * without a CORS preflight the server refuses, so this defeats CSRF even where
 * a browser ignores SameSite.
 */
const CLIENT_HEADER = { 'X-Bastion-Client': 'web' };

let accessToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;
let reauthHandler: (() => Promise<boolean>) | null = null;

export interface ApiUser {
  id: number;
  email: string;
  name: string | null;
  role: 'USER' | 'ADMIN';
  mfaEnabled: boolean;
}

export class ApiError extends Error {
  status: number;
  code?: string;
  fields?: Record<string, string>;

  constructor(status: number, message: string, code?: string, fields?: Record<string, string>) {
    super(message);
    this.status = status;
    this.code = code;
    this.fields = fields;
  }
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

/**
 * Registers the UI that asks the user to confirm it's them (password + code, or a
 * passkey). Called when the server answers REAUTH_REQUIRED; resolves true once the
 * user has re-authenticated, and the original request is retried.
 */
export function setReauthHandler(handler: (() => Promise<boolean>) | null): void {
  reauthHandler = handler;
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
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
        headers: CLIENT_HEADER,
      });
      if (res.ok) {
        const body = (await res.json()) as { accessToken: string };
        accessToken = body.accessToken;
        return true;
      }
      // Another tab may have rotated the cookie a moment ago; by now the browser
      // holds the new one. Try once more before concluding the session is over.
      if (res.status === 401 && attempt === 0) {
        await new Promise((resolve) => setTimeout(resolve, 400));
        continue;
      }
    } catch {
      // network error: fall through
    }
    break;
  }
  accessToken = null;
  return false;
}

async function rawRequest(path: string, options: RequestInit): Promise<Response> {
  const headers = new Headers(options.headers);
  headers.set('X-Bastion-Client', 'web');
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  return fetch(`${API_BASE}${path}`, { ...options, headers, credentials: 'include' });
}

async function toError(res: Response): Promise<ApiError> {
  let message = `Request failed (${res.status})`;
  let code: string | undefined;
  let fields: Record<string, string> | undefined;
  try {
    const body = (await res.json()) as { message?: string; code?: string; fields?: Record<string, string> };
    if (body.message) message = body.message;
    code = body.code;
    fields = body.fields;
  } catch {
    // Non-JSON error body; keep the generic message.
  }
  return new ApiError(res.status, message, code, fields);
}

/** JSON request with one silent-refresh retry on 401 and one re-auth retry when asked. */
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  let res = await rawRequest(path, options);

  if (res.status === 401 && !path.startsWith('/auth/')) {
    if (await refreshSession()) {
      res = await rawRequest(path, options);
    }
  }

  if (!res.ok) {
    const error = await toError(res);
    if (error.code === 'REAUTH_REQUIRED' && reauthHandler && (await reauthHandler())) {
      res = await rawRequest(path, options);
      if (!res.ok) throw await toError(res);
    } else {
      throw error;
    }
  }

  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

/** A readable message for any thrown value. */
export function messageOf(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof DOMException && err.name === 'NotAllowedError') {
    return 'The passkey prompt was cancelled or timed out.';
  }
  return 'Could not reach the server';
}
