import { request } from './api';
import { AuthTokenResponse, LoginCredentials, User } from '../types/auth';

export const authService = {
  async login(credentials: LoginCredentials): Promise<AuthTokenResponse> {
    return request<AuthTokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
  },

  async logout(token: string): Promise<{ message: string }> {
    return request<{ message: string }>('/auth/logout', {
      method: 'POST',
      token,
    });
  },

  async getMe(token: string): Promise<User> {
    return request<User>('/auth/me', {
      method: 'GET',
      token,
    });
  },
};
