import { useState, useEffect, useCallback, createContext, useContext, ReactNode } from 'react';
import React from 'react';
import { User, LoginCredentials, UserRole } from '../types/auth';
import { authService } from '../services/auth';
import { ApiError } from '../types/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  role: UserRole | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: ApiError | null;
  login: (credentials: LoginCredentials) => Promise<boolean>;
  logout: () => void;
  clearError: () => void;
}

const TOKEN_KEY = 'sdpp_auth_token';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ApiError | null>(null);

  const clearError = useCallback(() => setError(null), []);

  const logout = useCallback(async () => {
    if (token) {
      try {
        await authService.logout(token);
      } catch {
        // Ignore network errors on logout and continue cleanup
      }
    }
    sessionStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
    setError(null);
  }, [token]);

  const verifySession = useCallback(async (activeToken: string) => {
    setIsLoading(true);
    try {
      const profile = await authService.getMe(activeToken);
      setUser(profile);
      setError(null);
    } catch (err) {
      // Token is invalid/expired
      sessionStorage.removeItem(TOKEN_KEY);
      setToken(null);
      setUser(null);
      if (err instanceof ApiError && err.code !== 'UNAUTHORIZED') {
        setError(err);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (token) {
      verifySession(token);
    } else {
      setIsLoading(false);
    }
  }, [token, verifySession]);

  const login = async (credentials: LoginCredentials): Promise<boolean> => {
    setIsLoading(true);
    setError(null);
    try {
      const tokenRes = await authService.login(credentials);
      sessionStorage.setItem(TOKEN_KEY, tokenRes.access_token);
      setToken(tokenRes.access_token);

      // Fetch user profile immediately
      const profile = await authService.getMe(tokenRes.access_token);
      setUser(profile);
      return true;
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err);
      } else {
        setError(new ApiError('An unexpected authentication error occurred.', 'AUTH_ERROR', 500));
      }
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const value: AuthContextType = {
    user,
    token,
    role: user?.role || null,
    isAuthenticated: !!user && !!token,
    isLoading,
    error,
    login,
    logout,
    clearError,
  };

  return React.createElement(AuthContext.Provider, { value }, children);
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
