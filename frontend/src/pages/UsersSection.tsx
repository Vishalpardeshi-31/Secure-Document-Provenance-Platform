import React, { useState, useEffect, useCallback } from 'react';
import { User, Department, UserRole } from '../types/auth';
import { adminService } from '../services/admin';
import { useAuth } from '../hooks/useAuth';
import { ErrorBanner } from '../components/ErrorBanner';
import { StatusBadge } from '../components/StatusBadge';
import { formatDate } from '../lib/utils';
import { UserPlus, KeyRound, Check } from 'lucide-react';

interface UsersSectionProps {
  departments: Department[];
}

export const UsersSection: React.FC<UsersSectionProps> = ({ departments }) => {
  const { token, user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form toggle
  const [showCreateForm, setShowCreateForm] = useState<boolean>(false);
  const [resetTargetUser, setResetTargetUser] = useState<User | null>(null);

  // Create User Form State
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newConfirmPassword, setNewConfirmPassword] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('RECIPIENT');
  const [newDepartmentId, setNewDepartmentId] = useState<string>('');
  const [formSubmitting, setFormSubmitting] = useState<boolean>(false);

  // Reset Password State
  const [resetPasswordVal, setResetPasswordVal] = useState('');
  const [resetConfirmPasswordVal, setResetConfirmPasswordVal] = useState('');
  const [resetSubmitting, setResetSubmitting] = useState<boolean>(false);

  const fetchUsers = useCallback(async () => {
    if (!token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await adminService.getUsers(token);
      setUsers(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load users.');
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setError(null);
    setSuccessMsg(null);

    // Frontend validations
    if (!newUsername.trim() || newUsername.length < 3) {
      setError('Username must be at least 3 characters.');
      return;
    }
    if (!newEmail.trim() || !newEmail.includes('@')) {
      setError('A valid email address is required.');
      return;
    }
    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }
    if (newPassword !== newConfirmPassword) {
      setError('Password and confirmation password do not match.');
      return;
    }

    setFormSubmitting(true);
    try {
      await adminService.createUser(token, {
        username: newUsername.trim(),
        email: newEmail.trim(),
        password: newPassword,
        role: newRole,
        department_id: newDepartmentId || null,
      });

      setSuccessMsg(`User '${newUsername.trim()}' created successfully.`);
      setShowCreateForm(false);
      setNewUsername('');
      setNewEmail('');
      setNewPassword('');
      setNewConfirmPassword('');
      setNewDepartmentId('');
      await fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create user.');
    } finally {
      setFormSubmitting(false);
    }
  };

  const handleToggleActive = async (user: User) => {
    if (!token) return;
    setError(null);
    setSuccessMsg(null);
    try {
      await adminService.updateUser(token, user.id, {
        is_active: !user.is_active,
      });
      setSuccessMsg(`User '${user.username}' status updated to ${!user.is_active ? 'ACTIVE' : 'DEACTIVATED'}.`);
      await fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update user status.');
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !resetTargetUser) return;
    setError(null);
    setSuccessMsg(null);

    if (resetPasswordVal.length < 12) {
      setError('New password must be at least 12 characters.');
      return;
    }
    if (resetPasswordVal !== resetConfirmPasswordVal) {
      setError('New password and confirmation do not match.');
      return;
    }

    setResetSubmitting(true);
    try {
      await adminService.resetPassword(token, resetTargetUser.id, resetPasswordVal);
      setSuccessMsg(`Password for '${resetTargetUser.username}' securely reset.`);
      setResetTargetUser(null);
      setResetPasswordVal('');
      setResetConfirmPasswordVal('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reset password.');
    } finally {
      setResetSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header with Title & Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h2 className="text-base font-semibold text-slate-100 tracking-wide uppercase font-mono">
            Users
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Database-backed enterprise user accounts and credential management.
          </p>
        </div>
        <button
          onClick={() => {
            setShowCreateForm(!showCreateForm);
            setError(null);
          }}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-medium uppercase tracking-wider transition-colors self-start sm:self-auto"
        >
          <UserPlus className="w-3.5 h-3.5" />
          {showCreateForm ? 'Cancel' : '+ Create User'}
        </button>
      </div>

      {error && <ErrorBanner error={error} onDismiss={() => setError(null)} />}

      {successMsg && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-800 text-emerald-200 text-xs rounded flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Check className="w-4 h-4 text-emerald-400" />
            {successMsg}
          </span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">
            &times;
          </button>
        </div>
      )}

      {/* Create User Form */}
      {showCreateForm && (
        <div className="bg-surface border border-border p-5 rounded space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono border-b border-border-subtle pb-2">
            New User Registration
          </h3>

          <form onSubmit={handleCreateUser} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Username</label>
              <input
                type="text"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                required
                placeholder="e.g. officer_smith"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Email</label>
              <input
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                required
                placeholder="e.g. smith@agency.internal"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                placeholder="Min 12 chars, upper/lower/digit/symbol"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Confirm Password</label>
              <input
                type="password"
                value={newConfirmPassword}
                onChange={(e) => setNewConfirmPassword(e.target.value)}
                required
                placeholder="Confirm exact password"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Role</label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as UserRole)}
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="RECIPIENT">RECIPIENT</option>
                <option value="OFFICER">OFFICER</option>
                <option value="AUDITOR">AUDITOR</option>
                <option value="ADMIN">ADMIN</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Department</label>
              <select
                value={newDepartmentId}
                onChange={(e) => setNewDepartmentId(e.target.value)}
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="">None / Unassigned</option>
                {departments.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name} ({d.code})
                  </option>
                ))}
              </select>
            </div>

            <div className="sm:col-span-2 flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowCreateForm(false)}
                className="px-3 py-1.5 text-xs border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={formSubmitting}
                className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded font-medium disabled:opacity-50"
              >
                {formSubmitting ? 'Creating...' : 'Register User'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Password Reset Modal/Dialog */}
      {resetTargetUser && (
        <div className="bg-surface border border-amber-900/60 p-5 rounded space-y-3">
          <div className="flex items-center gap-2 text-amber-300">
            <KeyRound className="w-4 h-4" />
            <h3 className="text-xs font-semibold uppercase font-mono">
              Reset Password for {resetTargetUser.username}
            </h3>
          </div>
          <p className="text-[11px] text-slate-400">
            Enter a new enterprise-grade password (minimum 12 characters, uppercase, lowercase, digit, symbol).
          </p>

          <form onSubmit={handleResetPassword} className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            <div>
              <label className="block text-[10px] font-mono uppercase text-slate-400">New Password</label>
              <input
                type="password"
                value={resetPasswordVal}
                onChange={(e) => setResetPasswordVal(e.target.value)}
                required
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
              />
            </div>
            <div>
              <label className="block text-[10px] font-mono uppercase text-slate-400">Confirm New Password</label>
              <input
                type="password"
                value={resetConfirmPasswordVal}
                onChange={(e) => setResetConfirmPasswordVal(e.target.value)}
                required
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
              />
            </div>
            <div className="sm:col-span-2 flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setResetTargetUser(null)}
                className="px-3 py-1.5 text-xs border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={resetSubmitting}
                className="px-4 py-1.5 text-xs bg-amber-600 hover:bg-amber-500 text-white rounded font-medium disabled:opacity-50"
              >
                {resetSubmitting ? 'Resetting...' : 'Confirm Password Reset'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Users Table */}
      <div className="bg-surface border border-border rounded overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            Loading users from database...
          </div>
        ) : users.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            No users registered.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 border-b border-border text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-2.5 px-4">Username / Email</th>
                  <th className="py-2.5 px-4">Role</th>
                  <th className="py-2.5 px-4">Department</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Created</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-slate-300">
                {users.map((u) => {
                  const isSelf = currentUser?.id === u.id;
                  return (
                    <tr key={u.id} className="hover:bg-slate-900/30 transition-colors">
                      <td className="py-3 px-4">
                        <span className="font-semibold text-slate-100 block">{u.username}</span>
                        <span className="text-[11px] text-slate-400">{u.email}</span>
                      </td>
                      <td className="py-3 px-4">
                        <StatusBadge status={u.role} variant="role" />
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {u.department_name || (
                          <span className="text-slate-500 text-[11px]">Unassigned</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span className={u.is_active ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                          {u.is_active ? 'ACTIVE' : 'DEACTIVATED'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {formatDate(u.created_at)}
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => setResetTargetUser(u)}
                          title="Reset Password"
                          className="px-2 py-1 text-[11px] border border-slate-700 hover:border-amber-600 text-slate-300 hover:text-amber-300 rounded transition-colors"
                        >
                          Reset PW
                        </button>
                        {!isSelf && (
                          <button
                            onClick={() => handleToggleActive(u)}
                            className={`px-2 py-1 text-[11px] border rounded transition-colors ${
                              u.is_active
                                ? 'border-rose-900/60 text-rose-400 hover:bg-rose-950/40'
                                : 'border-emerald-900/60 text-emerald-400 hover:bg-emerald-950/40'
                            }`}
                          >
                            {u.is_active ? 'Deactivate' : 'Activate'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
