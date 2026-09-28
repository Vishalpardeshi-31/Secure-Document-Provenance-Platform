import time
from collections import defaultdict
from typing import Dict, List, Tuple
from fastapi import HTTPException, status, Request


class RateLimiter:
    """In-memory sliding-window rate limiter for sensitive authentication endpoints."""

    def __init__(self):
        # Maps key -> list of timestamp floats
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> None:
        """Checks if key exceeds max_requests within window_seconds.
        Raises HTTP 429 if exceeded."""
        now = time.time()
        cutoff = now - window_seconds

        # Clean old timestamps
        timestamps = [ts for ts in self._requests[key] if ts > cutoff]
        self._requests[key] = timestamps

        if len(timestamps) >= max_requests:
            retry_after = int(window_seconds - (now - timestamps[0])) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )

        self._requests[key].append(now)

    def record_attempt(self, key: str) -> None:
        self._requests[key].append(time.time())

    def reset(self, key: str) -> None:
        if key in self._requests:
            del self._requests[key]


# Global rate limiter instances
auth_rate_limiter = RateLimiter()


def get_client_ip(request: Request) -> str:
    """Safely extracts client IP address from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"
