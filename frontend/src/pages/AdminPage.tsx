import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { api, ApiError, messageOf } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { device, Status, when } from './account/common';

interface AdminUser {
  id: number;
  email: string;
  name: string | null;
  role: 'USER' | 'ADMIN';
  enabled: boolean;
  locked: boolean;
  mfaEnabled: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}

interface Paged<T> {
  content: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

interface EventRow {
  id: number;
  occurredAt: string;
  type: string;
  userId: number | null;
  email: string | null;
  actorUserId: number | null;
  ip: string | null;
  userAgent: string | null;
  detail: string | null;
}

interface Detail {
  user: AdminUser;
  passwordChangedAt: string | null;
  passkeys: number;
  sessions: { method: string; ip: string | null; userAgent: string | null; createdAt: string; lastSeenAt: string }[];
  recentEvents: EventRow[];
}

type Tab = 'users' | 'events' | 'settings';

function Pager({ data, onPage }: { data: Paged<unknown>; onPage: (p: number) => void }) {
  return (
    <div className="pager">
      <button type="button" disabled={data.page === 0} onClick={() => onPage(data.page - 1)}>
        ← Prev
      </button>
      <span>
        Page {data.page + 1} of {Math.max(1, data.totalPages)} · {data.totalElements} total
      </span>
      <button type="button" disabled={data.page >= data.totalPages - 1} onClick={() => onPage(data.page + 1)}>
        Next →
      </button>
    </div>
  );
}

function EventsTable({ rows }: { rows: EventRow[] }) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Event</th>
            <th>Account</th>
            <th>By admin</th>
            <th>IP</th>
            <th>Device</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e) => (
            <tr key={e.id} className={/FAILED|BLOCKED|REUSE|REFUSED/.test(e.type) ? 'row-warn' : undefined}>
              <td>{when(e.occurredAt)}</td>
              <td>{e.type}</td>
              <td>{e.email ?? (e.userId ? `#${e.userId}` : '—')}</td>
              <td>{e.actorUserId ? `#${e.actorUserId}` : ''}</td>
              <td>{e.ip ?? '—'}</td>
              <td>{device(e.userAgent)}</td>
              <td>{e.detail ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UsersTab() {
  const { user: me } = useAuth();
  const [data, setData] = useState<Paged<AdminUser> | null>(null);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState('');
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api<Paged<AdminUser>>(`/admin/users?page=${page}&size=20&q=${encodeURIComponent(search)}`));
    } catch (err) {
      setError(messageOf(err));
    }
  }, [page, search]);

  useEffect(() => {
    load();
  }, [load]);

  async function open(u: AdminUser) {
    setError('');
    try {
      setDetail(await api<Detail>(`/admin/users/${u.id}`));
    } catch (err) {
      setError(messageOf(err));
    }
  }

  async function act(u: AdminUser, message: string, request: () => Promise<unknown>) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await request();
      setNotice(message);
      await load();
      if (detail?.user.id === u.id) await open(u);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  const put = (path: string, body: unknown) => api(path, { method: 'PUT', body: JSON.stringify(body) });

  function submitSearch(e: FormEvent) {
    e.preventDefault();
    setPage(0);
    setSearch(query.trim());
  }

  return (
    <>
      <Status error={error} notice={notice} />
      <form className="inline-form" onSubmit={submitSearch}>
        <input aria-label="Search users" placeholder="Search by email or name" value={query}
               onChange={(e) => setQuery(e.target.value)} />
        <button type="submit">Search</button>
      </form>
      {data && (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>2FA</th>
                  <th>Last sign-in</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.content.map((u) => {
                  const self = u.id === me?.id;
                  return (
                    <tr key={u.id}>
                      <td>
                        <button type="button" className="link-button" onClick={() => open(u)}>
                          {u.email}
                        </button>
                      </td>
                      <td>{u.role}</td>
                      <td>{u.locked ? 'Locked' : u.enabled ? 'Active' : 'Unverified'}</td>
                      <td>{u.mfaEnabled ? 'On' : '—'}</td>
                      <td>{when(u.lastLoginAt)}</td>
                      <td className="row-actions">
                        {self ? (
                          <span className="hint">(you)</span>
                        ) : (
                          <>
                            <button type="button" disabled={busy} onClick={() => act(u, 'Role updated',
                              () => put(`/admin/users/${u.id}/role`, { role: u.role === 'ADMIN' ? 'USER' : 'ADMIN' }))}>
                              {u.role === 'ADMIN' ? 'Remove admin' : 'Make admin'}
                            </button>
                            <button type="button" disabled={busy} onClick={() => act(u, u.locked ? 'Unlocked' : 'Locked and signed out',
                              () => put(`/admin/users/${u.id}/locked`, { locked: !u.locked }))}>
                              {u.locked ? 'Unlock' : 'Lock'}
                            </button>
                            <button type="button" disabled={busy} onClick={() => act(u, 'Signed out everywhere',
                              () => api(`/admin/users/${u.id}/sessions/revoke`, { method: 'POST' }))}>
                              Sign out
                            </button>
                            {u.mfaEnabled && (
                              <button type="button" disabled={busy} onClick={() =>
                                window.confirm(`Turn off two-factor for ${u.email}? Only do this after verifying who's asking.`)
                                && act(u, 'Two-factor reset', () => api(`/admin/users/${u.id}/mfa`, { method: 'DELETE' }))}>
                                Reset 2FA
                              </button>
                            )}
                            <button type="button" className="danger" disabled={busy} onClick={() =>
                              window.confirm(`Permanently delete ${u.email}? This cannot be undone.`)
                              && act(u, 'Account deleted', () => api(`/admin/users/${u.id}`, { method: 'DELETE' }))}>
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
          <Pager data={data} onPage={setPage} />
        </>
      )}
      {detail && (
        <div className="card detail-panel">
          <div className="detail-header">
            <h2>{detail.user.email}</h2>
            <button type="button" className="secondary" onClick={() => setDetail(null)}>
              Close
            </button>
          </div>
          <p className="hint">
            Joined {when(detail.user.createdAt)} · password changed {when(detail.passwordChangedAt)} ·{' '}
            {detail.passkeys} passkey{detail.passkeys === 1 ? '' : 's'} · 2FA {detail.user.mfaEnabled ? 'on' : 'off'}
          </p>
          <h3>Active sessions ({detail.sessions.length})</h3>
          <ul className="plain-list">
            {detail.sessions.map((s, i) => (
              <li key={i}>
                {device(s.userAgent)} · {s.ip ?? '—'} · {s.method} · last active {when(s.lastSeenAt)}
              </li>
            ))}
          </ul>
          <h3>Recent security events</h3>
          <EventsTable rows={detail.recentEvents} />
        </div>
      )}
    </>
  );
}

function EventsTab() {
  const [data, setData] = useState<Paged<EventRow> | null>(null);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState({ email: '', ip: '', type: '' });
  const [applied, setApplied] = useState(filters);
  const [error, setError] = useState('');

  useEffect(() => {
    const params = new URLSearchParams({ page: String(page), size: '50' });
    Object.entries(applied).forEach(([k, v]) => v && params.set(k, v));
    api<Paged<EventRow>>(`/admin/security-events?${params}`).then(setData).catch((err) => setError(messageOf(err)));
  }, [page, applied]);

  function apply(e: FormEvent) {
    e.preventDefault();
    setPage(0);
    setApplied({ ...filters });
  }

  return (
    <>
      <Status error={error} />
      <form className="inline-form" onSubmit={apply}>
        <input aria-label="Email" placeholder="Email" value={filters.email}
               onChange={(e) => setFilters({ ...filters, email: e.target.value })} />
        <input aria-label="IP address" placeholder="IP address" value={filters.ip}
               onChange={(e) => setFilters({ ...filters, ip: e.target.value })} />
        <input aria-label="Event type" placeholder="Type, e.g. SIGN_IN_FAILED" value={filters.type}
               onChange={(e) => setFilters({ ...filters, type: e.target.value.toUpperCase() })} />
        <button type="submit">Filter</button>
      </form>
      {data && (
        <>
          <EventsTable rows={data.content} />
          <Pager data={data} onPage={setPage} />
        </>
      )}
    </>
  );
}

function SettingsTab() {
  const [signupsOpen, setSignupsOpen] = useState<boolean | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api<{ signupsOpen: boolean }>('/admin/settings').then((s) => setSignupsOpen(s.signupsOpen))
      .catch((err) => setError(messageOf(err)));
  }, []);

  async function toggle() {
    setError('');
    try {
      const s = await api<{ signupsOpen: boolean }>('/admin/settings', {
        method: 'PUT',
        body: JSON.stringify({ signupsOpen: !signupsOpen }),
      });
      setSignupsOpen(s.signupsOpen);
    } catch (err) {
      setError(messageOf(err));
    }
  }

  return (
    <>
      <Status error={error} />
      {signupsOpen !== null && (
        <p>
          New accounts are <strong>{signupsOpen ? 'open' : 'closed'}</strong>.{' '}
          <button type="button" className="secondary" onClick={toggle}>
            {signupsOpen ? 'Close signups' : 'Open signups'}
          </button>
        </p>
      )}
      <p className="hint">Close signups during an abuse wave, or for an invite-only launch. Existing users are unaffected.</p>
    </>
  );
}

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>('users');
  const [blocked, setBlocked] = useState('');

  // The admin API refuses sessions that didn't sign in with two factors; say why up front.
  useEffect(() => {
    api('/admin/settings').catch((err) => {
      if (err instanceof ApiError && err.code === 'ADMIN_MFA_REQUIRED') setBlocked(err.message);
    });
  }, []);

  if (blocked) {
    return (
      <div className="card">
        <h1>Administration</h1>
        <p className="alert alert-error">{blocked}</p>
        <p>
          <Link to="/account">Set up two-factor authentication or a passkey</Link>.
        </p>
      </div>
    );
  }

  return (
    <div className="card card-wide">
      <h1>Administration</h1>
      <div className="tabs" role="tablist">
        {(['users', 'events', 'settings'] as Tab[]).map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} className={tab === t ? 'tab active' : 'tab'}
                  onClick={() => setTab(t)}>
            {t === 'users' ? 'Users' : t === 'events' ? 'Security log' : 'Settings'}
          </button>
        ))}
      </div>
      {tab === 'users' && <UsersTab />}
      {tab === 'events' && <EventsTab />}
      {tab === 'settings' && <SettingsTab />}
    </div>
  );
}
