import { request } from './api';
import { SystemHealth } from '../types/system';

export const healthService = {
  async getHealth(): Promise<SystemHealth> {
    return request<SystemHealth>('/health', {
      method: 'GET',
    });
  },
};
