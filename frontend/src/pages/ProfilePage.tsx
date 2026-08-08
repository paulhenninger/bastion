import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';

interface Profile {
  id: number;
  email: string;
  name: string | null;
  role: 'USER' | 'ADMIN';
}

export default function ProfilePage() {
  const { user, setUser } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState(user?.name ?? '');
  const [profileMsg, setProfileMsg] = useState('');
  const [profileErr, setProfileErr] = useState('');

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [passwordErr, setPasswordErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function saveProfile(e: FormEvent) {
    e.preventDefault();
    setProfileMsg('');
    setProfileErr('');
    try {
      const updated = await api<Profile>('/users/me', {
        method: 'PUT',
        body: JSON.stringify({ name: name || null }),
      });
      setUser({ id: updated.id, email: updated.email, name: updated.name, role: updated.role });
      setProfileMsg('Profile saved');
    } catch (err) {
      setProfileErr(err instanceof ApiError ? err.message : 'Could not reach the server');
    }
  }

  async function changePassword(e: FormEvent) {
    e.preventDefault();
    setPasswordErr('');
    setBusy(true);
    try {
      await api('/users/me/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      // Every session (including this one) was revoked; sign in again.
      setUser(null);
      navigate('/login');
    } catch (err) {
      setPasswordErr(err instanceof ApiError ? err.message : 'Could not reach the server');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="card">
        <h1>Profile</h1>
        {profileMsg && (
          <p className="alert alert-success" role="status">
            {profileMsg}
          </p>
        )}
        {profileErr && (
          <p className="alert alert-error" role="alert">
            {profileErr}
          </p>
        )}
        <form onSubmit={saveProfile}>
          <label htmlFor="profile-email">Email</label>
          <input id="profile-email" type="email" value={user?.email ?? ''} disabled />
          <label htmlFor="profile-name">Name</label>
          <input
            id="profile-name"
            type="text"
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <button type="submit">Save</button>
        </form>
      </div>

      <div className="card">
        <h2>Change password</h2>
        <p className="hint">
          Changing your password signs you out everywhere, this device included.
        </p>
        {passwordErr && (
          <p className="alert alert-error" role="alert">
            {passwordErr}
          </p>
        )}
        <form onSubmit={changePassword}>
          <label htmlFor="current-password">Current password</label>
          <input
            id="current-password"
            type="password"
            autoComplete="current-password"
            required
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <label htmlFor="new-password">New password (at least 8 characters)</label>
          <input
            id="new-password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <button type="submit" disabled={busy}>
            {busy ? 'Changing…' : 'Change password'}
          </button>
        </form>
      </div>
    </>
  );
}
