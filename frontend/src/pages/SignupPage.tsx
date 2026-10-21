import { useCallback, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { signup } from '../api/auth';
import { ApiError, messageOf } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { Turnstile } from '../components/Turnstile';

export default function SignupPage() {
  const { config } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [captcha, setCaptcha] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [done, setDone] = useState('');
  const [busy, setBusy] = useState(false);
  const onCaptcha = useCallback((token: string | null) => setCaptcha(token), []);
  const minLength = config?.passwordMinLength ?? 12;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setFieldErrors({});
    setBusy(true);
    try {
      setDone(await signup(email, password, name, captcha));
    } catch (err) {
      setError(messageOf(err));
      if (err instanceof ApiError) setFieldErrors(err.fields ?? {});
    } finally {
      setBusy(false);
    }
  }

  if (config && !config.signupsOpen) {
    return (
      <div className="card auth-card">
        <h1>Create account</h1>
        <p className="alert alert-error">New accounts can't be created right now.</p>
      </div>
    );
  }

  if (done) {
    return (
      <div className="card auth-card">
        <h1>Check your email</h1>
        <p className="alert alert-success" role="status">
          {done}
        </p>
        <p className="hint">
          The link expires in 24 hours. You'll be asked for the password you just chose when you open it.
        </p>
      </div>
    );
  }

  return (
    <div className="card auth-card">
      <h1>Create account</h1>
      {error && (
        <p className="alert alert-error" role="alert">
          {error}
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <label htmlFor="name">Name (optional)</label>
        <input id="name" type="text" autoComplete="name" maxLength={100} value={name}
               onChange={(e) => setName(e.target.value)} />
        <label htmlFor="email">Email</label>
        <input id="email" type="email" autoComplete="email" required maxLength={254} value={email}
               onChange={(e) => setEmail(e.target.value)} />
        {fieldErrors.email && <p className="field-error">{fieldErrors.email}</p>}
        <label htmlFor="password">Password (at least {minLength} characters)</label>
        <input id="password" type="password" autoComplete="new-password" required minLength={minLength}
               maxLength={config?.passwordMaxLength ?? 128} value={password}
               onChange={(e) => setPassword(e.target.value)} />
        <p className="hint">
          A passphrase of a few unrelated words is long, memorable and strong. We check new passwords against
          known data breaches without ever sending them anywhere.
        </p>
        {config?.turnstileSiteKey && <Turnstile siteKey={config.turnstileSiteKey} onToken={onCaptcha} />}
        <button type="submit" disabled={busy || (!!config?.turnstileSiteKey && !captcha)}>
          {busy ? 'Creating…' : 'Create account'}
        </button>
      </form>
      <p className="auth-links">
        <Link to="/login">Already have an account? Sign in</Link>
      </p>
    </div>
  );
}
