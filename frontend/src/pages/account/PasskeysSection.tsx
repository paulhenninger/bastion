import { useCallback, useEffect, useState } from 'react';
import { api, messageOf } from '../../api/client';
import { createPasskey, CreationOptionsJSON, defaultPasskeyLabel, passkeysSupported } from '../../api/webauthn';
import { Section, Status, when } from './common';

interface Passkey {
  id: number;
  label: string;
  synced: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export function PasskeysSection() {
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api<Passkey[]>('/users/me/passkeys').then(setPasskeys).catch((err) => setError(messageOf(err)));
  }, []);

  useEffect(load, [load]);

  async function run(action: () => Promise<void>) {
    setError('');
    setNotice('');
    setBusy(true);
    try {
      await action();
      load();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  const add = () =>
    run(async () => {
      const options = await api<CreationOptionsJSON>('/users/me/passkeys/options', { method: 'POST' });
      const body = await createPasskey(options, defaultPasskeyLabel());
      await api('/users/me/passkeys', { method: 'POST', body: JSON.stringify(body) });
      setNotice('Passkey added. You can now sign in with it — no password needed.');
    });

  const rename = (p: Passkey) => {
    const label = window.prompt('Name this passkey', p.label);
    if (!label) return;
    return run(async () => {
      await api(`/users/me/passkeys/${p.id}`, { method: 'PATCH', body: JSON.stringify({ label }) });
    });
  };

  const remove = (p: Passkey) => {
    if (!window.confirm(`Remove the passkey "${p.label}"? It will no longer sign in.`)) return;
    return run(async () => {
      await api(`/users/me/passkeys/${p.id}`, { method: 'DELETE' });
    });
  };

  return (
    <Section id="passkeys" title="Passkeys">
      <p className="hint">
        A passkey signs you in with your fingerprint, face or device PIN. It can't be phished or reused, and
        counts as two-factor sign-in on its own.
      </p>
      <Status error={error} notice={notice} />
      {passkeys.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Added</th>
                <th>Last used</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {passkeys.map((p) => (
                <tr key={p.id}>
                  <td>
                    {p.label} {p.synced && <span className="badge">synced</span>}
                  </td>
                  <td>{when(p.createdAt)}</td>
                  <td>{when(p.lastUsedAt)}</td>
                  <td className="row-actions">
                    <button type="button" disabled={busy} onClick={() => rename(p)}>
                      Rename
                    </button>
                    <button type="button" className="danger" disabled={busy} onClick={() => remove(p)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {passkeysSupported() ? (
        <button type="button" disabled={busy} onClick={add}>
          Add a passkey
        </button>
      ) : (
        <p className="hint">This browser doesn't support passkeys.</p>
      )}
    </Section>
  );
}
