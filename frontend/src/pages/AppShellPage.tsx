import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../hooks/useAuth';
import { AppLayout } from '../layouts/AppLayout';
import { UsersSection } from './UsersSection';
import { DepartmentsSection } from './DepartmentsSection';
import { DevicesSection } from './DevicesSection';
import { AuditSection } from './AuditSection';
import { SessionSection } from './SessionSection';
import { DocumentsSection } from './DocumentsSection';
import { RecipientKeysSection } from './RecipientKeysSection';
import { Department } from '../types/auth';
import { adminService } from '../services/admin';

export const AppShellPage: React.FC = () => {
  const { user, token } = useAuth();
  const [departments, setDepartments] = useState<Department[]>([]);

  // Dynamically compute authorized tabs based strictly on backend verified user.role
  const role = user?.role;

  const getAvailableTabs = () => {
    switch (role) {
      case 'ADMIN':
        return [
          { id: 'documents', label: 'Documents' },
          { id: 'recipient_keys', label: 'Recipient Keys' },
          { id: 'users', label: 'Users' },
          { id: 'departments', label: 'Departments' },
          { id: 'devices', label: 'Registered Devices' },
          { id: 'audit', label: 'Audit Trail' },
          { id: 'session', label: 'Active Session' },
        ];
      case 'OFFICER':
        return [
          { id: 'documents', label: 'Documents' },
          { id: 'devices', label: 'Registered Devices' },
          { id: 'session', label: 'Active Session' },
        ];
      case 'AUDITOR':
        return [
          { id: 'audit', label: 'Audit / Provenance' },
          { id: 'devices', label: 'Registered Devices' },
          { id: 'session', label: 'Active Session' },
        ];
      case 'RECIPIENT':
        return [
          { id: 'documents', label: 'Assigned Documents' },
          { id: 'session', label: 'Active Session' },
          { id: 'devices', label: 'Registered Devices' },
        ];
      default:
        return [
          { id: 'session', label: 'Active Session' },
          { id: 'devices', label: 'Registered Devices' },
        ];
    }
  };

  const tabs = getAvailableTabs();
  const [activeTab, setActiveTab] = useState<string>(() => {
    if (role === 'ADMIN') return 'documents';
    if (role === 'OFFICER') return 'documents';
    if (role === 'RECIPIENT') return 'documents';
    if (role === 'AUDITOR') return 'audit';
    return 'session';
  });

  // Ensure activeTab is always one of the valid tabs for this role
  useEffect(() => {
    if (!tabs.some((t) => t.id === activeTab)) {
      setActiveTab(tabs[0]?.id || 'session');
    }
  }, [role, tabs, activeTab]);

  // Load departments if admin or recipient
  const fetchDepartments = useCallback(async () => {
    if (!token) return;
    try {
      const data = await adminService.getDepartments(token);
      setDepartments(data);
    } catch {
      // Non-admins or errors fail gracefully
    }
  }, [token]);

  useEffect(() => {
    fetchDepartments();
  }, [fetchDepartments]);

  if (!user) return null;

  return (
    <AppLayout
      activeTab={activeTab}
      onTabChange={setActiveTab}
      availableTabs={tabs}
    >
      <div className="space-y-6">
        {activeTab === 'documents' && (role === 'ADMIN' || role === 'OFFICER' || role === 'RECIPIENT') && (
          <DocumentsSection />
        )}

        {activeTab === 'recipient_keys' && role === 'ADMIN' && (
          <RecipientKeysSection />
        )}

        {activeTab === 'users' && role === 'ADMIN' && (
          <UsersSection departments={departments} />
        )}

        {activeTab === 'departments' && role === 'ADMIN' && (
          <DepartmentsSection
            departments={departments}
            onRefresh={fetchDepartments}
          />
        )}

        {activeTab === 'devices' && <DevicesSection />}

        {activeTab === 'audit' && (role === 'ADMIN' || role === 'AUDITOR') && (
          <AuditSection />
        )}

        {activeTab === 'session' && <SessionSection />}
      </div>
    </AppLayout>
  );
};
