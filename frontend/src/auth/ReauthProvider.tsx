import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { api, messageOf, setReauthHandler } from '../api/client';
import { getAssertion, passkeysSupported, RequestOptionsJSON } from '../api/webauthn';

interface ReauthStatus {
  reauthenticatedUntil: string | null;
  totpEnabled: boolean;
  hasPasskeys: boolean;
}

/**
 * "Confirm it's you." Sensitive actions (2FA, passkeys, email, deletion, admin actions)
 * need a re-authentication within the last few minutes. When the server answers
 * REAUTH_REQUIRED, the API client calls the handler registered here; this dialog asks
 * for the password (+ authenticator code) or a passkey, and the original request is
 * retried automatically once the user confirms.
 */
export function ReauthProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<ReauthStatus | null>(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const resolver = useRef<((ok: boolean) => void) | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);

  const finish = useCallback((ok: boolean) => {
    resolver.current?.(ok);
    resolver.current = null;
    setOpen(false);
    setPassword('');
    setCode('');
    setError('');
  }, []);

  useEffect(() => {
    setReauthHandler(
      () =>
        new Promise<boolean>((resolve) => {
          resolver.current = resolve;
          setOpen(true);
          api<ReauthStatus>('/users/me/reauth').then(setStatus).catch(() => setStatus(null));
        }),
    );
    return () => setReauthHandler(null);
  }, []);

  useEffect(() => {
    if (open) dialog.current?.showModal();
    else dialog.current?.close();
  }, [open]);

  async function withPassword(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('/users/me/reauth', {
        method: 'POST',
        body: JSON.stringify({ password, code: code || null }),
      });
      finish(true);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  async function withPasskey() {
    setBusy(true);
    setError('');
    try {
      const options = await api<RequestOptionsJSON>('/users/me/reauth/passkey/options', { method: 'POST' });
      const assertion = await getAssertion(options);
      await api('/users/me/reauth/passkey', { method: 'POST', body: JSON.stringify(assertion) });
      finish(true);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {children}
      <dialog ref={dialog} className="modal" onCancel={() => finish(false)} aria-labelledby="reauth-title">
        <h2 id="reauth-title">Confirm it's you</h2>
        <p className="hint">This is a sensitive change, so we need you to sign in again first.</p>
        {error && (
          <p className="alert alert-error" role="alert">
            {error}
          </p>
        )}
        {status?.hasPasskeys && passkeysSupported() && (
          <>
            <button type="button" disabled={busy} onClick={withPasskey}>
              Use a passkey
            </button>
            <p className="divider">or</p>
          </>
        )}
        <form onSubmit={withPassword}>
          <label htmlFor="reauth-password">Password</label>
          <input
            id="reauth-password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {status?.totpEnabled && (
            <>
              <label htmlFor="reauth-code">Authenticator code (or a recovery code)</label>
              <input
                id="reauth-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                required
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </>
          )}
          <div className="button-row">
            <button type="submit" disabled={busy}>
              {busy ? 'Checking…' : 'Confirm'}
            </button>
            <button type="button" className="secondary" onClick={() => finish(false)}>
              Cancel
            </button>
          </div>
        </form>
      </dialog>
    </>
  );
}
