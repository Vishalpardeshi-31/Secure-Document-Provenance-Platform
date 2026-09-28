import React from 'react';
import { AuthProvider, useAuth } from './hooks/useAuth';
import { AuthPage } from './pages/AuthPage';
import { AppShellPage } from './pages/AppShellPage';

const AppContent: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center text-slate-400 font-mono text-xs">
        <div className="w-8 h-8 border-2 border-slate-700 border-t-blue-500 rounded-full animate-spin mb-3" />
        <span>INITIALIZING SECURITY PERIMETER...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <AuthPage />;
  }

  return <AppShellPage />;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;
