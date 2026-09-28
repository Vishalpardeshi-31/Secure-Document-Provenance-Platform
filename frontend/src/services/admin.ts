import { request } from './api';
import {
  User,
  CreateUserPayload,
  UpdateUserPayload,
  Department,
  CreateDepartmentPayload,
  UpdateDepartmentPayload,
  Device,
  RegisterDevicePayload,
  AuditEvent,
} from '../types/auth';

export const adminService = {
  // User Management
  async getUsers(token: string): Promise<User[]> {
    return request<User[]>('/users', {
      method: 'GET',
      token,
    });
  },

  async createUser(token: string, payload: CreateUserPayload): Promise<User> {
    return request<User>('/users', {
      method: 'POST',
      token,
      body: JSON.stringify(payload),
    });
  },

  async updateUser(token: string, userId: string, payload: UpdateUserPayload): Promise<User> {
    return request<User>(`/users/${userId}`, {
      method: 'PATCH',
      token,
      body: JSON.stringify(payload),
    });
  },

  async resetPassword(token: string, userId: string, newPassword: string): Promise<{ message: string }> {
    return request<{ message: string }>(`/users/${userId}/reset-password`, {
      method: 'POST',
      token,
      body: JSON.stringify({ new_password: newPassword }),
    });
  },

  // Department Management
  async getDepartments(token: string): Promise<Department[]> {
    return request<Department[]>('/departments', {
      method: 'GET',
      token,
    });
  },

  async createDepartment(token: string, payload: CreateDepartmentPayload): Promise<Department> {
    return request<Department>('/departments', {
      method: 'POST',
      token,
      body: JSON.stringify(payload),
    });
  },

  async updateDepartment(token: string, departmentId: string, payload: UpdateDepartmentPayload): Promise<Department> {
    return request<Department>(`/departments/${departmentId}`, {
      method: 'PATCH',
      token,
      body: JSON.stringify(payload),
    });
  },

  async deleteDepartment(token: string, departmentId: string): Promise<{ message: string }> {
    return request<{ message: string }>(`/departments/${departmentId}`, {
      method: 'DELETE',
      token,
    });
  },

  // Device Registration Foundation
  async getDevices(token: string): Promise<Device[]> {
    return request<Device[]>('/devices', {
      method: 'GET',
      token,
    });
  },

  async registerDevice(token: string, payload: RegisterDevicePayload): Promise<Device> {
    return request<Device>('/devices', {
      method: 'POST',
      token,
      body: JSON.stringify(payload),
    });
  },

  async updateDeviceStatus(token: string, deviceId: string, status: string): Promise<Device> {
    return request<Device>(`/devices/${deviceId}`, {
      method: 'PATCH',
      token,
      body: JSON.stringify({ registration_status: status }),
    });
  },

  async deleteDevice(token: string, deviceId: string): Promise<{ message: string }> {
    return request<{ message: string }>(`/devices/${deviceId}`, {
      method: 'DELETE',
      token,
    });
  },

  // Audit Events
  async getAuditEvents(token: string): Promise<AuditEvent[]> {
    return request<AuditEvent[]>('/audit/events', {
      method: 'GET',
      token,
    });
  },
};
