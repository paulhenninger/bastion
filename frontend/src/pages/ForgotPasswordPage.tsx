import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { forgotPassword } from '../api/auth';
import { ApiError } from '../api/client';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      setNotice(await forgotPassword(email));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not reach the server');
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
            <input
              id="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <button type="submit" disabled={busy}>
              {busy ? 'Sending…' : 'Email me a reset link'}
            </button>
          </form>
        </>
      )}
      <p className="auth-links">
        <Link to="/login">Back to sign in</Link>
      </p>
    </div>
  );
}
