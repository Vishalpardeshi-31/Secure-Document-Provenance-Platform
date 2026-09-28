import React, { useState } from 'react';
import { Department } from '../types/auth';
import { adminService } from '../services/admin';
import { useAuth } from '../hooks/useAuth';
import { ErrorBanner } from '../components/ErrorBanner';
import { formatDate } from '../lib/utils';
import { Plus, Check } from 'lucide-react';

interface DepartmentsSectionProps {
  departments: Department[];
  onRefresh: () => Promise<void>;
}

export const DepartmentsSection: React.FC<DepartmentsSectionProps> = ({
  departments,
  onRefresh,
}) => {
  const { token } = useAuth();
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [code, setCode] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Edit Department State
  const [editingDept, setEditingDept] = useState<Department | null>(null);
  const [editName, setEditName] = useState('');
  const [editCode, setEditCode] = useState('');
  const [editDesc, setEditDesc] = useState('');
  const [editActive, setEditActive] = useState(true);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setError(null);
    setSuccessMsg(null);

    if (!name.trim()) {
      setError('Department name is required.');
      return;
    }
    if (!code.trim()) {
      setError('Department code is required.');
      return;
    }

    setIsSubmitting(true);
    try {
      await adminService.createDepartment(token, {
        name: name.trim(),
        code: code.trim().toUpperCase(),
        description: description.trim() || null,
      });
      setSuccessMsg(`Department '${name.trim()}' created successfully.`);
      setShowCreate(false);
      setName('');
      setCode('');
      setDescription('');
      await onRefresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create department.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStartEdit = (dept: Department) => {
    setEditingDept(dept);
    setEditName(dept.name);
    setEditCode(dept.code);
    setEditDesc(dept.description || '');
    setEditActive(dept.is_active);
    setError(null);
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !editingDept) return;
    setError(null);
    setSuccessMsg(null);

    setIsSubmitting(true);
    try {
      await adminService.updateDepartment(token, editingDept.id, {
        name: editName.trim(),
        code: editCode.trim().toUpperCase(),
        description: editDesc.trim() || null,
        is_active: editActive,
      });
      setSuccessMsg(`Department '${editName.trim()}' updated.`);
      setEditingDept(null);
      await onRefresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update department.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (dept: Department) => {
    if (!token) return;
    if (!window.confirm(`Are you sure you want to delete department '${dept.name}'?`)) return;
    setError(null);
    setSuccessMsg(null);

    try {
      await adminService.deleteDepartment(token, dept.id);
      setSuccessMsg(`Department '${dept.name}' deleted.`);
      await onRefresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete department.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h2 className="text-base font-semibold text-slate-100 tracking-wide uppercase font-mono">
            Departments
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Organizational units for security boundary isolation and access control.
          </p>
        </div>
        <button
          onClick={() => {
            setShowCreate(!showCreate);
            setError(null);
          }}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-medium uppercase tracking-wider transition-colors self-start sm:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          {showCreate ? 'Cancel' : '+ Create Department'}
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

      {/* Create Department Form */}
      {showCreate && (
        <div className="bg-surface border border-border p-5 rounded space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono border-b border-border-subtle pb-2">
            Register Department
          </h3>
          <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Department Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                placeholder="e.g. Threat Intelligence Directorate"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Department Code</label>
              <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
                placeholder="e.g. THREAT_INTEL"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono uppercase"
              />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-[11px] font-mono uppercase text-slate-400">Description (Optional)</label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Department mission and security scope"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
              />
            </div>
            <div className="sm:col-span-2 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="px-3 py-1.5 text-xs border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded font-medium disabled:opacity-50"
              >
                {isSubmitting ? 'Registering...' : 'Save Department'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Edit Department Modal/Inline */}
      {editingDept && (
        <div className="bg-surface border border-slate-700 p-5 rounded space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono border-b border-border-subtle pb-2">
            Edit Department: {editingDept.name}
          </h3>
          <form onSubmit={handleSaveEdit} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Department Name</label>
              <input
                type="text"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                required
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Department Code</label>
              <input
                type="text"
                value={editCode}
                onChange={(e) => setEditCode(e.target.value)}
                required
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono uppercase"
              />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-[11px] font-mono uppercase text-slate-400">Description</label>
              <input
                type="text"
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="editActiveCheckbox"
                checked={editActive}
                onChange={(e) => setEditActive(e.target.checked)}
                className="rounded border-slate-700 bg-slate-950 text-blue-600"
              />
              <label htmlFor="editActiveCheckbox" className="text-xs text-slate-300 font-mono">
                Department Active
              </label>
            </div>
            <div className="sm:col-span-2 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setEditingDept(null)}
                className="px-3 py-1.5 text-xs border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded font-medium disabled:opacity-50"
              >
                {isSubmitting ? 'Updating...' : 'Save Changes'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Departments Table */}
      <div className="bg-surface border border-border rounded overflow-hidden">
        {departments.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            No departments defined in PostgreSQL. Click "+ Create Department" to initialize.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 border-b border-border text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-2.5 px-4">Name / Code</th>
                  <th className="py-2.5 px-4">Description</th>
                  <th className="py-2.5 px-4">Assigned Users</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Created</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-slate-300">
                {departments.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-900/30 transition-colors">
                    <td className="py-3 px-4">
                      <span className="font-semibold text-slate-100 block">{d.name}</span>
                      <span className="text-[10px] text-slate-400 bg-slate-900 px-1 py-0.5 rounded border border-slate-800">
                        {d.code}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 max-w-xs truncate">
                      {d.description || '—'}
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {d.user_count} user(s)
                    </td>
                    <td className="py-3 px-4">
                      <span className={d.is_active ? 'text-emerald-400 font-semibold' : 'text-slate-500 font-semibold'}>
                        {d.is_active ? 'ACTIVE' : 'INACTIVE'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {formatDate(d.created_at)}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <button
                        onClick={() => handleStartEdit(d)}
                        className="px-2 py-1 text-[11px] border border-slate-700 hover:border-slate-500 text-slate-300 rounded transition-colors"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(d)}
                        className="px-2 py-1 text-[11px] border border-rose-900/60 text-rose-400 hover:bg-rose-950/40 rounded transition-colors"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
