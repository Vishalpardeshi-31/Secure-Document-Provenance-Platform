import React, { useState, useEffect, useCallback } from 'react';
import { Device } from '../types/auth';
import { adminService } from '../services/admin';
import { useAuth } from '../hooks/useAuth';
import { ErrorBanner } from '../components/ErrorBanner';
import { formatDate } from '../lib/utils';
import { Laptop, Plus, Check, AlertCircle } from 'lucide-react';

export const DevicesSection: React.FC = () => {
  const { token } = useAuth();
  const [devices, setDevices] = useState<Device[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form State
  const [showRegister, setShowRegister] = useState<boolean>(false);
  const [deviceName, setDeviceName] = useState<string>('');
  const [deviceFingerprint, setDeviceFingerprint] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const fetchDevices = useCallback(async () => {
    if (!token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await adminService.getDevices(token);
      setDevices(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve registered devices.');
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  const handleGenerateLocalFingerprint = () => {
    // Generate a non-invasive pseudo-random client instance fingerprint
    const randPart = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    setDeviceFingerprint(`dev-fp-${randPart}`);
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setError(null);
    setSuccessMsg(null);

    if (!deviceName.trim()) {
      setError('Human-readable device name is required.');
      return;
    }
    if (!deviceFingerprint.trim() || deviceFingerprint.length < 16) {
      setError('Device fingerprint identifier must be at least 16 characters.');
      return;
    }

    setIsSubmitting(true);
    try {
      await adminService.registerDevice(token, {
        device_name: deviceName.trim(),
        device_fingerprint: deviceFingerprint.trim(),
      });
      setSuccessMsg(`Device '${deviceName.trim()}' successfully registered.`);
      setShowRegister(false);
      setDeviceName('');
      setDeviceFingerprint('');
      await fetchDevices();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to register device.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUpdateStatus = async (device: Device, newStatus: string) => {
    if (!token) return;
    setError(null);
    setSuccessMsg(null);
    try {
      await adminService.updateDeviceStatus(token, device.id, newStatus);
      setSuccessMsg(`Device '${device.device_name}' status set to ${newStatus}.`);
      await fetchDevices();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update device status.');
    }
  };

  const handleDelete = async (device: Device) => {
    if (!token) return;
    if (!window.confirm(`Unregister device '${device.device_name}'?`)) return;
    setError(null);
    setSuccessMsg(null);
    try {
      await adminService.deleteDevice(token, device.id);
      setSuccessMsg(`Device '${device.device_name}' unregistered.`);
      await fetchDevices();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to remove device.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h2 className="text-base font-semibold text-slate-100 tracking-wide uppercase font-mono">
            Device Registration Foundation
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Database-tracked hardware client registrations for session policy enforcement.
          </p>
        </div>
        <button
          onClick={() => {
            setShowRegister(!showRegister);
            if (!showRegister && !deviceFingerprint) {
              handleGenerateLocalFingerprint();
            }
            setError(null);
          }}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-medium uppercase tracking-wider transition-colors self-start sm:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          {showRegister ? 'Cancel' : '+ Register Device'}
        </button>
      </div>

      {/* Security Scope Notice */}
      <div className="border border-slate-800 bg-slate-900/40 p-3 rounded text-[11px] text-slate-400 font-mono flex items-start gap-2.5">
        <AlertCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          Device foundation establishes database records for client authorization tracking.
          Browser fingerprints are not treated as cryptographically bound hardware identities;
          asymmetric key encapsulation and hardware-bound decryption will be implemented in subsequent cryptographic phases.
        </p>
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

      {/* Register Device Form */}
      {showRegister && (
        <div className="bg-surface border border-border p-5 rounded space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono border-b border-border-subtle pb-2">
            Register Authorized Hardware / Client Device
          </h3>
          <form onSubmit={handleRegister} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400">Device Name</label>
              <input
                type="text"
                value={deviceName}
                onChange={(e) => setDeviceName(e.target.value)}
                required
                placeholder="e.g. Secured Workstation 04"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
              />
            </div>
            <div>
              <div className="flex items-center justify-between">
                <label className="block text-[11px] font-mono uppercase text-slate-400">Client Identifier / Fingerprint</label>
                <button
                  type="button"
                  onClick={handleGenerateLocalFingerprint}
                  className="text-[10px] text-blue-400 hover:text-blue-300 font-mono"
                >
                  Generate Local ID
                </button>
              </div>
              <input
                type="text"
                value={deviceFingerprint}
                onChange={(e) => setDeviceFingerprint(e.target.value)}
                required
                placeholder="Client instance fingerprint string"
                className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
              />
            </div>
            <div className="sm:col-span-2 flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setShowRegister(false)}
                className="px-3 py-1.5 text-xs border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded font-medium disabled:opacity-50"
              >
                {isSubmitting ? 'Registering...' : 'Register Device'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Devices Table */}
      <div className="bg-surface border border-border rounded overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            Querying registered devices...
          </div>
        ) : devices.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            No devices registered for this identity.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 border-b border-border text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-2.5 px-4">Device Name</th>
                  <th className="py-2.5 px-4">Identifier / Fingerprint</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Registered At</th>
                  <th className="py-2.5 px-4">Last Seen</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-slate-300">
                {devices.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-900/30 transition-colors">
                    <td className="py-3 px-4">
                      <span className="font-semibold text-slate-100 flex items-center gap-2">
                        <Laptop className="w-3.5 h-3.5 text-slate-400" />
                        {d.device_name}
                      </span>
                      <span className="text-[10px] text-slate-500 block truncate max-w-xs">{d.id}</span>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                      {d.device_fingerprint}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`text-[11px] font-semibold px-2 py-0.5 rounded border ${
                          d.registration_status === 'ACTIVE'
                            ? 'bg-emerald-950/40 border-emerald-800 text-emerald-400'
                            : d.registration_status === 'REVOKED'
                            ? 'bg-rose-950/40 border-rose-800 text-rose-400'
                            : 'bg-amber-950/40 border-amber-800 text-amber-400'
                        }`}
                      >
                        {d.registration_status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {formatDate(d.created_at)}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {d.last_seen_at ? formatDate(d.last_seen_at) : '—'}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      {d.registration_status !== 'REVOKED' ? (
                        <button
                          onClick={() => handleUpdateStatus(d, 'REVOKED')}
                          className="px-2 py-1 text-[11px] border border-rose-900/60 text-rose-400 hover:bg-rose-950/40 rounded transition-colors"
                        >
                          Revoke
                        </button>
                      ) : (
                        <button
                          onClick={() => handleUpdateStatus(d, 'ACTIVE')}
                          className="px-2 py-1 text-[11px] border border-emerald-900/60 text-emerald-400 hover:bg-emerald-950/40 rounded transition-colors"
                        >
                          Activate
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(d)}
                        className="px-2 py-1 text-[11px] border border-slate-700 text-slate-400 hover:text-rose-300 rounded transition-colors"
                      >
                        Remove
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
