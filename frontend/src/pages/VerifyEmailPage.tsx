import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { takeTokenFromFragment, verifyEmail } from '../api/auth';
import { messageOf } from '../api/client';
import { useAuth } from '../auth/AuthContext';

/**
 * The verification link proves you read the inbox; the password proves you're the
 * person who signed up. Asking for both is what stops someone else registering your
 * address first with a password they know (account pre-hijacking).
 */
export default function VerifyEmailPage() {
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const [token] = useState(takeTokenFromFragment);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      setUser(await verifyEmail(token, password));
      navigate('/', { replace: true });
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <div className="card auth-card">
        <h1>Verify your email</h1>
        <p className="alert alert-error" role="alert">
          This link is missing its token. Open the link from your email again, or sign up again for a new one.
        </p>
        <p className="auth-links">
          <Link to="/login">Back to sign in</Link>
        </p>
      </div>
    );
  }

  return (
    <div className="card auth-card">
      <h1>Activate your account</h1>
      <p className="hint">Enter the password you chose when you signed up.</p>
      {error && (
        <p className="alert alert-error" role="alert">
          {error}
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <label htmlFor="password">Password</label>
        <input id="password" type="password" autoComplete="current-password" required autoFocus
               value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit" disabled={busy}>
          {busy ? 'Activating…' : 'Activate account'}
        </button>
      </form>
    </div>
  );
}
