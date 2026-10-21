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
import { getConfig, logout as apiLogout, PublicConfig } from '../api/auth';

interface AuthState {
  user: ApiUser | null;
  config: PublicConfig | null;
  /** True until the boot-time silent refresh has resolved. */
  loading: boolean;
  /** The password used to sign in appears in a public breach; nudge a change. */
  passwordBreached: boolean;
  setUser: (user: ApiUser | null) => void;
  setPasswordBreached: (breached: boolean) => void;
  refreshUser: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<ApiUser | null>(null);
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [passwordBreached, setPasswordBreached] = useState(false);

  // On boot, fetch public config and try to resume the session from the refresh cookie.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      getConfig().then((c) => !cancelled && setConfig(c)).catch(() => undefined);
      if (await refreshSession()) {
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

  const refreshUser = useCallback(async () => {
    setUser(await api<ApiUser>('/users/me'));
  }, []);

  const signOut = useCallback(async () => {
    await apiLogout();
    setUser(null);
    setPasswordBreached(false);
  }, []);

  const value = useMemo(
    () => ({ user, config, loading, passwordBreached, setUser, setPasswordBreached, refreshUser, signOut }),
    [user, config, loading, passwordBreached, refreshUser, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
