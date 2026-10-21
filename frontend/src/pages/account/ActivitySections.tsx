import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, messageOf, setAccessToken } from '../../api/client';
import { useAuth } from '../../auth/AuthContext';
import { device, Section, Status, when } from './common';

interface SessionRow {
  id: string;
  method: string;
  ip: string | null;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
}

interface ActivityRow {
  occurredAt: string;
  type: string;
  ip: string | null;
  userAgent: string | null;
  detail: string | null;
}

const METHOD: Record<string, string> = {
  PASSWORD: 'Password',
  PASSWORD_TOTP: 'Password + authenticator',
  PASSWORD_RECOVERY_CODE: 'Password + recovery code',
  PASSKEY: 'Passkey',
  EMAIL_VERIFICATION: 'Email verification',
};

export function SessionsSection() {
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const load = useCallback(() => {
    api<SessionRow[]>('/users/me/sessions').then(setSessions).catch((err) => setError(messageOf(err)));
  }, []);

  useEffect(load, [load]);

  async function revoke(s: SessionRow) {
    setError('');
    try {
      await api(`/users/me/sessions/${encodeURIComponent(s.id)}`, { method: 'DELETE' });
      load();
    } catch (err) {
      setError(messageOf(err));
    }
  }

  async function revokeOthers() {
    setError('');
    try {
      const res = await api<{ revoked: number }>('/users/me/sessions/revoke-others', { method: 'POST' });
      setNotice(`Signed out ${res.revoked} other session${res.revoked === 1 ? '' : 's'}.`);
      load();
    } catch (err) {
      setError(messageOf(err));
    }
  }

  return (
    <Section id="sessions" title="Where you're signed in">
      <Status error={error} notice={notice} />
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Signed in with</th>
              <th>IP</th>
              <th>Last active</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id}>
                <td>
                  {device(s.userAgent)} {s.current && <span className="badge">this device</span>}
                </td>
                <td>{METHOD[s.method] ?? s.method}</td>
                <td>{s.ip ?? '—'}</td>
                <td>{when(s.lastSeenAt)}</td>
                <td className="row-actions">
                  {!s.current && (
                    <button type="button" onClick={() => revoke(s)}>
                      Sign out
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sessions.length > 1 && (
        <button type="button" className="secondary" onClick={revokeOthers}>
          Sign out all other sessions
        </button>
      )}
    </Section>
  );
}

export function ActivitySection() {
  const [rows, setRows] = useState<ActivityRow[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api<ActivityRow[]>('/users/me/activity').then(setRows).catch((err) => setError(messageOf(err)));
  }, []);

  return (
    <Section id="activity" title="Recent security activity">
      <p className="hint">Sign-ins, failed attempts and changes to how your account can be accessed.</p>
      <Status error={error} />
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>What</th>
              <th>IP</th>
              <th>Device</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={/FAILED|BLOCKED|REUSE|REFUSED/.test(r.type) ? 'row-warn' : undefined}>
                <td>{when(r.occurredAt)}</td>
                <td>
                  {r.type.replaceAll('_', ' ').toLowerCase()}
                  {r.detail ? ` — ${r.detail}` : ''}
                </td>
                <td>{r.ip ?? '—'}</td>
                <td>{device(r.userAgent)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

export function DataSection() {
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');

  async function exportData() {
    setError('');
    try {
      const data = await api<unknown>('/users/me/export');
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = 'account-export.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(messageOf(err));
    }
  }

  async function deleteAccount() {
    if (!window.confirm('Permanently delete your account and all its data? This cannot be undone.')) return;
    setError('');
    try {
      await api('/users/me', { method: 'DELETE' });
      setAccessToken(null);
      setUser(null);
      navigate('/login');
    } catch (err) {
      setError(messageOf(err));
    }
  }

  return (
    <Section id="data" title="Your data">
      <Status error={error} />
      <p className="hint">Download everything we store about you, or delete your account for good.</p>
      <div className="button-row">
        <button type="button" className="secondary" onClick={exportData}>
          Download my data
        </button>
        <button type="button" className="danger" onClick={deleteAccount}>
          Delete account
        </button>
      </div>
    </Section>
  );
}
