import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { signup } from '../api/auth';
import { ApiError } from '../api/client';

export default function SignupPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [done, setDone] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setFieldErrors({});
    setBusy(true);
    try {
      setDone(await signup(email, password, name));
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        setFieldErrors(err.fields ?? {});
      } else {
        setError('Could not reach the server');
      }
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="card auth-card">
        <h1>Almost there</h1>
        <p className="alert alert-success" role="status">
          {done}
        </p>
        <p>
          Once you've clicked the link in the email, you can{' '}
          <Link to="/login">sign in</Link>.
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
        <input
          id="name"
          type="text"
          autoComplete="name"
          maxLength={100}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        {fieldErrors.email && <p className="field-error">{fieldErrors.email}</p>}
        <label htmlFor="password">Password (at least 8 characters)</label>
        <input
          id="password"
          type="password"
          autoComplete="new-password"
          required
          minLength={8}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {fieldErrors.password && <p className="field-error">{fieldErrors.password}</p>}
        <button type="submit" disabled={busy}>
          {busy ? 'Creating…' : 'Create account'}
        </button>
      </form>
      <p className="auth-links">
        <Link to="/login">Already have an account? Sign in</Link>
      </p>
    </div>
  );
}
