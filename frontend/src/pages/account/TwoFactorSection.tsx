import QRCode from 'qrcode';
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { api, messageOf } from '../../api/client';
import { useAuth } from '../../auth/AuthContext';
import { Section, Status } from './common';

interface MfaStatus {
  totpEnabled: boolean;
  recoveryCodesRemaining: number;
}

interface Setup {
  secret: string;
  otpauthUri: string;
}

/** Recovery codes are shown exactly once — offer a download so they actually get kept. */
function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const { config, user } = useAuth();

  function download() {
    const text = `${config?.appName ?? 'Bastion'} recovery codes for ${user?.email}\n`
      + `Each code works once. Keep them somewhere safe.\n\n${codes.join('\n')}\n`;
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="recovery-codes">
      <p className="alert alert-success" role="status">
        Save these recovery codes now — this is the only time they're shown. Each works once if you lose your phone.
      </p>
      <ul className="code-list">
        {codes.map((c) => (
          <li key={c}>
            <code>{c}</code>
          </li>
        ))}
      </ul>
      <div className="button-row">
        <button type="button" onClick={download}>
          Download
        </button>
        <button type="button" className="secondary" onClick={onDone}>
          I've saved them
        </button>
      </div>
    </div>
  );
}

export function TwoFactorSection() {
  const { refreshUser } = useAuth();
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [setup, setSetup] = useState<Setup | null>(null);
  const [qr, setQr] = useState('');
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api<MfaStatus>('/users/me/mfa').then(setStatus).catch((err) => setError(messageOf(err)));
  }, []);

  useEffect(load, [load]);

  async function run(action: () => Promise<void>) {
    setError('');
    setBusy(true);
    try {
      await action();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  const begin = () =>
    run(async () => {
      const s = await api<Setup>('/users/me/mfa/totp/setup', { method: 'POST' });
      setSetup(s);
      // Rendered locally: the secret never goes to a third-party QR service.
      setQr(await QRCode.toDataURL(s.otpauthUri, { margin: 1, width: 200 }));
    });

  const enable = (e: FormEvent) => {
    e.preventDefault();
    return run(async () => {
      const res = await api<{ recoveryCodes: string[] }>('/users/me/mfa/totp/enable', {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
      setCodes(res.recoveryCodes);
      setSetup(null);
      setCode('');
      load();
      await refreshUser();
    });
  };

  const disable = () =>
    run(async () => {
      if (!window.confirm('Turn off two-factor authentication? Your account will be protected by your password alone.')) {
        return;
      }
      await api('/users/me/mfa/totp/disable', { method: 'POST' });
      load();
      await refreshUser();
    });

  const regenerate = () =>
    run(async () => {
      const res = await api<{ recoveryCodes: string[] }>('/users/me/mfa/recovery-codes', { method: 'POST' });
      setCodes(res.recoveryCodes);
      load();
    });

  return (
    <Section id="mfa" title="Two-factor authentication">
      <Status error={error} />
      {codes && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}
      {status?.totpEnabled ? (
        <>
          <p>
            ✅ On — signing in needs a code from your authenticator app.{' '}
            <span className="hint">{status.recoveryCodesRemaining} recovery codes left.</span>
          </p>
          <div className="button-row">
            <button type="button" className="secondary" disabled={busy} onClick={regenerate}>
              New recovery codes
            </button>
            <button type="button" className="danger" disabled={busy} onClick={disable}>
              Turn off
            </button>
          </div>
        </>
      ) : setup ? (
        <form onSubmit={enable}>
          <p>Scan this with an authenticator app (1Password, Google Authenticator, Authy, Aegis…):</p>
          {qr && <img className="qr" src={qr} alt="QR code for your authenticator app" width={200} height={200} />}
          <p className="hint">
            Can't scan? Enter this key: <code className="secret">{setup.secret}</code>
          </p>
          <label htmlFor="totp-code">Then enter the 6-digit code it shows</label>
          <input id="totp-code" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6}
                 required value={code} onChange={(e) => setCode(e.target.value)} />
          <button type="submit" disabled={busy}>
            Turn on
          </button>
        </form>
      ) : (
        <>
          <p className="hint">
            Add a second step at sign-in with an authenticator app, so a stolen password alone isn't enough.
            Administrators must use two-factor authentication or a passkey.
          </p>
          <button type="button" disabled={busy || !status} onClick={begin}>
            Set up authenticator app
          </button>
        </>
      )}
    </Section>
  );
}
