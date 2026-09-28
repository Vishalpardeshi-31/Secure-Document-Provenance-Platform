import { useState, useEffect, useCallback } from 'react';
import { SystemHealth } from '../types/system';
import { healthService } from '../services/health';
import { ApiError } from '../types/api';

export function useSystemStatus() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ApiError | null>(null);

  const checkStatus = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await healthService.getHealth();
      setHealth(data);
      setError(null);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err);
      } else {
        setError(new ApiError('System connectivity test failed.', 'UNAVAILABLE', 0));
      }
      setHealth(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkStatus();
  }, [checkStatus]);

  return {
    health,
    isLoading,
    error,
    refreshStatus: checkStatus,
  };
}
