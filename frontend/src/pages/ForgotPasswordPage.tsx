import { useCallback, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { forgotPassword } from '../api/auth';
import { messageOf } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { Turnstile } from '../components/Turnstile';

export default function ForgotPasswordPage() {
  const { config } = useAuth();
  const [email, setEmail] = useState('');
  const [captcha, setCaptcha] = useState<string | null>(null);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const onCaptcha = useCallback((token: string | null) => setCaptcha(token), []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      setNotice(await forgotPassword(email, captcha));
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card auth-card">
      <h1>Reset your password</h1>
      {notice ? (
        <p className="alert alert-success" role="status">
          {notice}
        </p>
      ) : (
        <>
          {error && (
            <p className="alert alert-error" role="alert">
              {error}
            </p>
          )}
          <form onSubmit={handleSubmit}>
            <label htmlFor="email">Email</label>
            <input id="email" type="email" autoComplete="email" required value={email}
                   onChange={(e) => setEmail(e.target.value)} />
            {config?.turnstileSiteKey && <Turnstile siteKey={config.turnstileSiteKey} onToken={onCaptcha} />}
            <button type="submit" disabled={busy || (!!config?.turnstileSiteKey && !captcha)}>
              {busy ? 'Sending…' : 'Email me a reset link'}
            </button>
          </form>
          <p className="hint">
            Resetting your password doesn't turn off two-factor authentication — you'll still need your
            authenticator or a recovery code to sign in.
          </p>
        </>
      )}
      <p className="auth-links">
        <Link to="/login">Back to sign in</Link>
      </p>
    </div>
  );
}
