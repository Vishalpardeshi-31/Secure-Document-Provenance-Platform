export interface ErrorDetail {
  field?: string | null;
  message: string;
}

export interface ApiErrorPayload {
  error: {
    code: string;
    message: string;
    details?: ErrorDetail[];
  };
}

export class ApiError extends Error {
  code: string;
  statusCode: number;
  details: ErrorDetail[];

  constructor(message: string, code: string = 'UNKNOWN_ERROR', statusCode: number = 500, details: ErrorDetail[] = []) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}
