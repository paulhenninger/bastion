import { Link } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

export default function DashboardPage() {
  const { user, passwordBreached } = useAuth();

  return (
    <>
      {passwordBreached && (
        <p className="alert alert-error" role="alert">
          The password you signed in with appears in a public data breach, so attackers will try it.{' '}
          <Link to="/account">Change it now</Link>.
        </p>
      )}
      {user?.role === 'ADMIN' && !user.mfaEnabled && (
        <p className="alert alert-error" role="alert">
          Administrators must use two-factor authentication or a passkey.{' '}
          <Link to="/account">Set one up</Link>, then sign in again.
        </p>
      )}
      <div className="card">
        <h1>Welcome{user?.name ? `, ${user.name}` : ''}</h1>
        <p>
          You're signed in as <strong>{user?.email}</strong>
          {user?.role === 'ADMIN' && ' (admin)'}.
        </p>
        {!user?.mfaEnabled && (
          <p className="hint">
            Tip: add a <Link to="/account">passkey or two-factor authentication</Link> so a stolen password
            alone can't get into your account.
          </p>
        )}
        <p>
          This page is the blank canvas — everything around it (signup, verification, sessions, two-factor,
          passkeys, recovery, the admin area) is already wired up. Start building your product here.
        </p>
      </div>
    </>
  );
}
