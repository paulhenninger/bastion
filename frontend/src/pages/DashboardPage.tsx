import { useAuth } from '../auth/AuthContext';

export default function DashboardPage() {
  const { user } = useAuth();

  return (
    <div className="card">
      <h1>Welcome{user?.name ? `, ${user.name}` : ''} 👋</h1>
      <p>
        You're signed in as <strong>{user?.email}</strong>
        {user?.role === 'ADMIN' && ' (admin)'}.
      </p>
      <p>
        This page is the blank canvas — everything around it (signup, email
        verification, sessions, password recovery, the admin area) is already
        wired up. Start building your product here.
      </p>
    </div>
  );
}
