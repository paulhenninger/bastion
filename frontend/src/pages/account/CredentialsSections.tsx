import { useState, type FormEvent } from 'react';
import { api, messageOf } from '../../api/client';
import { useAuth } from '../../auth/AuthContext';
import { Section, Status } from './common';

interface Profile {
  id: number;
  email: string;
  name: string | null;
  role: 'USER' | 'ADMIN';
  mfaEnabled: boolean;
}

export function ProfileSection() {
  const { user, setUser } = useAuth();
  const [name, setName] = useState(user?.name ?? '');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function save(e: FormEvent) {
    e.preventDefault();
    setError('');
    setNotice('');
    try {
      const p = await api<Profile>('/users/me', { method: 'PUT', body: JSON.stringify({ name: name || null }) });
      setUser({ id: p.id, email: p.email, name: p.name, role: p.role, mfaEnabled: p.mfaEnabled });
      setNotice('Saved');
    } catch (err) {
      setError(messageOf(err));
    }
  }

  return (
    <Section id="profile" title="Profile">
      <Status error={error} notice={notice} />
      <form onSubmit={save}>
        <label htmlFor="profile-name">Name</label>
        <input id="profile-name" type="text" maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        <button type="submit">Save</button>
      </form>
    </Section>
  );
}

export function EmailSection() {
  const { user } = useAuth();
  const [newEmail, setNewEmail] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setNotice('');
    setBusy(true);
    try {
      const res = await api<{ message: string }>('/users/me/email', {
        method: 'POST',
        body: JSON.stringify({ newEmail }),
      });
      setNotice(res.message);
      setNewEmail('');
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section id="email" title="Email address">
      <p className="hint">
        Currently <strong>{user?.email}</strong>. The change takes effect when you click the link we send to the new
        address, and you'll sign in again everywhere.
      </p>
      <Status error={error} notice={notice} />
      <form onSubmit={submit}>
        <label htmlFor="new-email">New email</label>
        <input id="new-email" type="email" autoComplete="email" required maxLength={254} value={newEmail}
               onChange={(e) => setNewEmail(e.target.value)} />
        <button type="submit" disabled={busy}>
          {busy ? 'Sending…' : 'Send confirmation link'}
        </button>
      </form>
    </Section>
  );
}

export function PasswordSection() {
  const { user, config, setPasswordBreached } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const minLength = config?.passwordMinLength ?? 12;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setNotice('');
    setBusy(true);
    try {
      const res = await api<{ message: string }>('/users/me/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword: current, newPassword: next, code: code || null }),
      });
      setNotice(res.message);
      setPasswordBreached(false);
      setCurrent('');
      setNext('');
      setCode('');
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section id="password" title="Password">
      <p className="hint">Changing your password signs out your other devices. This one stays signed in.</p>
      <Status error={error} notice={notice} />
      <form onSubmit={submit}>
        <input type="email" autoComplete="username" value={user?.email ?? ''} readOnly hidden />
        <label htmlFor="current-password">Current password</label>
        <input id="current-password" type="password" autoComplete="current-password" required value={current}
               onChange={(e) => setCurrent(e.target.value)} />
        <label htmlFor="new-password">New password (at least {minLength} characters)</label>
        <input id="new-password" type="password" autoComplete="new-password" required minLength={minLength}
               value={next} onChange={(e) => setNext(e.target.value)} />
        {user?.mfaEnabled && (
          <>
            <label htmlFor="password-code">Authenticator code</label>
            <input id="password-code" inputMode="numeric" autoComplete="one-time-code" required value={code}
                   onChange={(e) => setCode(e.target.value)} />
          </>
        )}
        <button type="submit" disabled={busy}>
          {busy ? 'Changing…' : 'Change password'}
        </button>
      </form>
    </Section>
  );
}
