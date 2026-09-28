import { ApiError, ApiErrorPayload } from '../types/api';

const envApiUrl = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/+$/, '');
const API_BASE = envApiUrl ? `${envApiUrl}/api/v1` : '/api/v1';

interface RequestOptions extends RequestInit {
  token?: string | null;
}

export async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { token, headers = {}, ...customConfig } = options;

  const requestHeaders: Record<string, string> = {
    ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
    ...(headers as Record<string, string>),
  };

  if (token) {
    requestHeaders['Authorization'] = `Bearer ${token}`;
  }

  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;

  let response: Response;
  try {
    response = await fetch(url, {
      ...customConfig,
      headers: requestHeaders,
    });
  } catch (networkError) {
    // API unavailable / network connection error
    throw new ApiError(
      'Unable to connect to the security backend. The server may be offline or unreachable.',
      'API_UNAVAILABLE',
      0
    );
  }

  // Parse JSON response body safely
  let data: unknown;
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    // Handle structured backend error format: { error: { code, message, details } }
    if (data && typeof data === 'object' && 'error' in data) {
      const errorPayload = data as ApiErrorPayload;
      throw new ApiError(
        errorPayload.error.message || 'An error occurred during request processing.',
        errorPayload.error.code || 'HTTP_ERROR',
        response.status,
        errorPayload.error.details || []
      );
    }

    // Fallbacks for specific status codes if not in standard format
    if (response.status === 401) {
      throw new ApiError('Authentication failed. Invalid or expired credentials.', 'UNAUTHORIZED', 401);
    }
    if (response.status === 403) {
      throw new ApiError('Access denied. Insufficient privileges.', 'FORBIDDEN', 403);
    }
    if (response.status === 422) {
      throw new ApiError('Submitted data failed validation constraints.', 'VALIDATION_ERROR', 422);
    }
    if (response.status >= 500) {
      throw new ApiError('Internal security platform error. Please contact an administrator.', 'SERVER_ERROR', response.status);
    }

    throw new ApiError(`Request failed with status code ${response.status}`, 'HTTP_ERROR', response.status);
  }

  return data as T;
}

export async function requestBlob(
  endpoint: string,
  options: RequestOptions = {}
): Promise<{ blob: Blob; contentType: string; filename?: string }> {
  const { token, headers = {}, ...customConfig } = options;

  const requestHeaders: Record<string, string> = {
    ...(headers as Record<string, string>),
  };

  if (token) {
    requestHeaders['Authorization'] = `Bearer ${token}`;
  }

  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;

  let response: Response;
  try {
    response = await fetch(url, {
      ...customConfig,
      headers: requestHeaders,
    });
  } catch {
    throw new ApiError(
      'Unable to connect to the security backend. The server may be offline or unreachable.',
      'API_UNAVAILABLE',
      0
    );
  }

  if (!response.ok) {
    let errorMsg = `Request failed with status code ${response.status}`;
    let errorCode = 'HTTP_ERROR';
    try {
      const errJson = await response.json();
      if (errJson && errJson.error) {
        errorMsg = errJson.error.message || errorMsg;
        errorCode = errJson.error.code || errorCode;
      }
    } catch {
      // not json
    }
    throw new ApiError(errorMsg, errorCode, response.status);
  }

  const blob = await response.blob();
  const contentType = response.headers.get('content-type') || 'application/octet-stream';
  const cd = response.headers.get('content-disposition');
  let filename: string | undefined;
  if (cd) {
    const match = cd.match(/filename="?([^"]+)"?/);
    if (match) filename = match[1];
  }

  return { blob, contentType, filename };
}
