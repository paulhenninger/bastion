import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { resetPassword, takeTokenFromFragment } from '../api/auth';
import { messageOf } from '../api/client';
import { useAuth } from '../auth/AuthContext';

export default function ResetPasswordPage() {
  const { config } = useAuth();
  const [token] = useState(takeTokenFromFragment);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const minLength = config?.passwordMinLength ?? 12;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }
    setBusy(true);
    try {
      setNotice(await resetPassword(token, password));
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <div className="card auth-card">
        <h1>Reset your password</h1>
        <p className="alert alert-error" role="alert">
          This link is missing its token. Request a new one.
        </p>
        <p className="auth-links">
          <Link to="/forgot-password">Request a new link</Link>
        </p>
      </div>
    );
  }

  return (
    <div className="card auth-card">
      <h1>Choose a new password</h1>
      {notice ? (
        <>
          <p className="alert alert-success" role="status">
            {notice}
          </p>
          <p className="auth-links">
            <Link to="/login">Sign in</Link>
          </p>
        </>
      ) : (
        <>
          {error && (
            <p className="alert alert-error" role="alert">
              {error}
            </p>
          )}
          <p className="hint">This signs you out on every device.</p>
          <form onSubmit={handleSubmit}>
            <label htmlFor="password">New password (at least {minLength} characters)</label>
            <input id="password" type="password" autoComplete="new-password" required minLength={minLength}
                   value={password} onChange={(e) => setPassword(e.target.value)} />
            <label htmlFor="confirm">Repeat new password</label>
            <input id="confirm" type="password" autoComplete="new-password" required value={confirm}
                   onChange={(e) => setConfirm(e.target.value)} />
            <button type="submit" disabled={busy}>
              {busy ? 'Saving…' : 'Set new password'}
            </button>
          </form>
        </>
      )}
    </div>
  );
}
