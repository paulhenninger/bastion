import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { verifyEmail } from '../api/auth';
import { ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';

export default function VerifyEmailPage() {
  const [params] = useSearchParams();
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  // StrictMode double-mounts effects in dev; the token is single-use, so guard.
  const fired = useRef(false);

  useEffect(() => {
    const token = params.get('token');
    if (!token) {
      setError('This link is missing its token.');
      return;
    }
    if (fired.current) return;
    fired.current = true;
    (async () => {
      try {
        const user = await verifyEmail(token);
        setUser(user);
        navigate('/', { replace: true });
      } catch (err) {
        setError(err instanceof ApiError ? err.message : 'Could not reach the server');
      }
    })();
  }, [params, setUser, navigate]);

  return (
    <div className="card auth-card">
      <h1>Verifying…</h1>
      {error ? (
        <>
          <p className="alert alert-error" role="alert">
            {error}
          </p>
          <p>
            <Link to="/login">Back to sign in</Link>
          </p>
        </>
      ) : (
        <p>Confirming your email address.</p>
      )}
    </div>
  );
}
