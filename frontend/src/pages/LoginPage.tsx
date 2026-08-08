import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { login, resendVerification } from '../api/auth';
import { ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';

export default function LoginPage() {
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [needsVerification, setNeedsVerification] = useState(false);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setNotice('');
    setBusy(true);
    try {
      const user = await login(email, password);
      setUser(user);
      navigate('/');
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        setNeedsVerification(err.status === 403 && err.message.includes('not verified'));
      } else {
        setError('Could not reach the server');
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleResend() {
    setError('');
    setNotice(await resendVerification(email));
    setNeedsVerification(false);
  }

  return (
    <div className="card auth-card">
      <h1>Sign in</h1>
      {error && (
        <p className="alert alert-error" role="alert">
          {error}
          {needsVerification && (
            <>
              {' '}
              <button type="button" className="link-button" onClick={handleResend}>
                Resend verification email
              </button>
            </>
          )}
        </p>
      )}
      {notice && (
        <p className="alert alert-success" role="status">
          {notice}
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
      <p className="auth-links">
        <Link to="/forgot-password">Forgot password?</Link>
        <Link to="/signup">Create an account</Link>
      </p>
    </div>
  );
}
