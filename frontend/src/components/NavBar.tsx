import { Link, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

export function NavBar() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();

  async function handleSignOut() {
    await signOut();
    navigate('/login');
  }

  return (
    <header className="navbar">
      <Link to="/" className="navbar-brand">
        ⬢ Bastion
      </Link>
      <nav className="navbar-links">
        {user ? (
          <>
            <NavLink to="/">Dashboard</NavLink>
            <NavLink to="/account">Account</NavLink>
            {user.role === 'ADMIN' && <NavLink to="/admin">Admin</NavLink>}
            <button type="button" className="link-button" onClick={handleSignOut}>
              Sign out
            </button>
          </>
        ) : (
          <>
            <NavLink to="/login">Sign in</NavLink>
            <NavLink to="/signup">Create account</NavLink>
          </>
        )}
      </nav>
    </header>
  );
}
