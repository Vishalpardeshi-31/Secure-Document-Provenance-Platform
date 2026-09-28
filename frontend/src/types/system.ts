export interface ComponentHealth {
  status: 'UP' | 'DOWN';
  latency_ms: number;
  details?: Record<string, unknown>;
}

export interface SystemHealth {
  status: 'HEALTHY' | 'DEGRADED';
  project: string;
  environment: string;
  timestamp: string;
  database: ComponentHealth;
}
