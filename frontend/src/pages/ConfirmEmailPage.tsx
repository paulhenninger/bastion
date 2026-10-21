import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { confirmEmailChange, takeTokenFromFragment } from '../api/auth';
import { messageOf, setAccessToken } from '../api/client';
import { useAuth } from '../auth/AuthContext';

/** Clicking the link sent to the NEW address completes an email change. */
export default function ConfirmEmailPage() {
  const { setUser } = useAuth();
  const [token] = useState(takeTokenFromFragment);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  // StrictMode double-runs effects in dev; the token is single-use.
  const fired = useRef(false);

  useEffect(() => {
    if (!token) {
      setError('This link is missing its token.');
      return;
    }
    if (fired.current) return;
    fired.current = true;
    confirmEmailChange(token)
      .then((message) => {
        // Every session ends when the sign-in address changes.
        setAccessToken(null);
        setUser(null);
        setNotice(message);
      })
      .catch((err) => setError(messageOf(err)));
  }, [token, setUser]);

  return (
    <div className="card auth-card">
      <h1>Confirm new email</h1>
      {notice && (
        <p className="alert alert-success" role="status">
          {notice}
        </p>
      )}
      {error && (
        <p className="alert alert-error" role="alert">
          {error}
        </p>
      )}
      {!notice && !error && <p>Confirming…</p>}
      <p className="auth-links">
        <Link to="/login">Sign in</Link>
      </p>
    </div>
  );
}
