import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';

interface AdminUser {
  id: number;
  email: string;
  name: string | null;
  role: 'USER' | 'ADMIN';
  enabled: boolean;
  locked: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}

interface Paged {
  content: AdminUser[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

export default function AdminPage() {
  const { user: me } = useAuth();
  const [data, setData] = useState<Paged | null>(null);
  const [page, setPage] = useState(0);
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState<number | null>(null);

  const load = useCallback(async (p: number) => {
    setError('');
    try {
      setData(await api<Paged>(`/admin/users?page=${p}&size=20`));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not reach the server');
    }
  }, []);

  useEffect(() => {
    load(page);
  }, [load, page]);

  async function act(user: AdminUser, action: () => Promise<unknown>) {
    setBusyId(user.id);
    setError('');
    try {
      await action();
      await load(page);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not reach the server');
    } finally {
      setBusyId(null);
    }
  }

  function toggleRole(user: AdminUser) {
    const role = user.role === 'ADMIN' ? 'USER' : 'ADMIN';
    return act(user, () =>
      api(`/admin/users/${user.id}/role`, { method: 'PUT', body: JSON.stringify({ role }) }),
    );
  }

  function toggleLocked(user: AdminUser) {
    return act(user, () =>
      api(`/admin/users/${user.id}/locked`, {
        method: 'PUT',
        body: JSON.stringify({ locked: !user.locked }),
      }),
    );
  }

  function remove(user: AdminUser) {
    if (!window.confirm(`Permanently delete ${user.email}? This cannot be undone.`)) {
      return;
    }
    return act(user, () => api(`/admin/users/${user.id}`, { method: 'DELETE' }));
  }

  return (
    <div className="card card-wide">
      <h1>Users</h1>
      {error && (
        <p className="alert alert-error" role="alert">
          {error}
        </p>
      )}
      {data && (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last login</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.content.map((u) => {
                  const self = u.id === me?.id;
                  return (
                    <tr key={u.id}>
                      <td>{u.email}</td>
                      <td>{u.name ?? '—'}</td>
                      <td>{u.role}</td>
                      <td>
                        {u.locked ? 'Locked' : u.enabled ? 'Active' : 'Unverified'}
                      </td>
                      <td>
                        {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'Never'}
                      </td>
                      <td className="row-actions">
                        {self ? (
                          <span className="hint">(you)</span>
                        ) : (
                          <>
                            <button
                              type="button"
                              disabled={busyId === u.id}
                              onClick={() => toggleRole(u)}
                            >
                              {u.role === 'ADMIN' ? 'Remove admin' : 'Make admin'}
                            </button>
                            <button
                              type="button"
                              disabled={busyId === u.id}
                              onClick={() => toggleLocked(u)}
                            >
                              {u.locked ? 'Unlock' : 'Lock'}
                            </button>
                            <button
                              type="button"
                              className="danger"
                              disabled={busyId === u.id}
                              onClick={() => remove(u)}
                            >
                              Delete
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="pager">
            <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>
              ← Prev
            </button>
            <span>
              Page {data.page + 1} of {Math.max(1, data.totalPages)} · {data.totalElements}{' '}
              accounts
            </span>
            <button
              type="button"
              disabled={page >= data.totalPages - 1}
              onClick={() => setPage(page + 1)}
            >
              Next →
            </button>
          </div>
        </>
      )}
    </div>
  );
}
