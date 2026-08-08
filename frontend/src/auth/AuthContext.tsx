import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { api, ApiUser, refreshSession } from '../api/client';
import { logout as apiLogout } from '../api/auth';

interface AuthState {
  user: ApiUser | null;
  /** True until the boot-time silent refresh has resolved. */
  loading: boolean;
  setUser: (user: ApiUser | null) => void;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<ApiUser | null>(null);
  const [loading, setLoading] = useState(true);

  // On boot, try to resume the session from the refresh cookie.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const resumed = await refreshSession();
      if (resumed) {
        try {
          const me = await api<ApiUser>('/users/me');
          if (!cancelled) setUser(me);
        } catch {
          // Session resumed but profile fetch failed; treat as signed out.
        }
      }
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const signOut = useCallback(async () => {
    await apiLogout();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, loading, setUser, signOut }),
    [user, loading, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
