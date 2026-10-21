import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { completeMfa, login, passkeyLogin, resendVerification } from '../api/auth';
import { ApiError, messageOf } from '../api/client';
import { passkeysSupported } from '../api/webauthn';
import { useAuth } from '../auth/AuthContext';

export default function LoginPage() {
  const { setUser, setPasswordBreached } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [needsVerification, setNeedsVerification] = useState(false);
  const [busy, setBusy] = useState(false);

  async function handlePassword(e: FormEvent) {
    e.preventDefault();
    setError('');
    setNotice('');
    setBusy(true);
    try {
      const result = await login(email, password);
      setPasswordBreached(result.passwordBreached);
      setPassword('');
      if (result.kind === 'mfa') {
        setMfaToken(result.mfaToken);
      } else {
        setUser(result.user);
        navigate('/');
      }
    } catch (err) {
      setError(messageOf(err));
      setNeedsVerification(err instanceof ApiError && err.code === 'EMAIL_NOT_VERIFIED');
    } finally {
      setBusy(false);
    }
  }

  async function handleCode(e: FormEvent) {
    e.preventDefault();
    if (!mfaToken) return;
    setError('');
    setBusy(true);
    try {
      setUser(await completeMfa(mfaToken, code));
      navigate('/');
    } catch (err) {
      setError(messageOf(err));
      setCode('');
      // A spent or expired challenge means starting over from the password.
      if (err instanceof ApiError && err.message.includes('expired')) setMfaToken(null);
    } finally {
      setBusy(false);
    }
  }

  async function handlePasskey() {
    setError('');
    setBusy(true);
    try {
      setUser(await passkeyLogin());
      navigate('/');
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleResend() {
    setError('');
    try {
      setNotice(await resendVerification(email, null));
    } catch (err) {
      setError(messageOf(err));
    }
    setNeedsVerification(false);
  }

  if (mfaToken) {
    return (
      <div className="card auth-card">
        <h1>Two-factor authentication</h1>
        <p className="hint">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
        {error && (
          <p className="alert alert-error" role="alert">
            {error}
          </p>
        )}
        <form onSubmit={handleCode}>
          <label htmlFor="code">Code</label>
          <input
            id="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoFocus
            required
            maxLength={32}
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <button type="submit" disabled={busy}>
            {busy ? 'Checking…' : 'Verify'}
          </button>
        </form>
        <p className="auth-links">
          <button type="button" className="link-button" onClick={() => setMfaToken(null)}>
            Start over
          </button>
        </p>
      </div>
    );
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
      {passkeysSupported() && (
        <>
          <button type="button" className="secondary full" disabled={busy} onClick={handlePasskey}>
            Sign in with a passkey
          </button>
          <p className="divider">or</p>
        </>
      )}
      <form onSubmit={handlePassword}>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          autoComplete="username webauthn"
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
