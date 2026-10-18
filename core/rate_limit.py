"""
core/rate_limit.py
Simple in-memory per-session rate limiter to prevent API abuse.
Default: max 10 requests per minute per session.
"""

import time
from typing import Dict, List


class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # In-memory session tracking: session_id -> list of timestamps
        self._history: Dict[str, List[float]] = {}

    def is_allowed(self, session_id: str) -> bool:
        """Check if session is within rate limit."""
        now = time.time()
        timestamps = self._history.get(session_id, [])
        
        # Purge timestamps outside the window
        valid_timestamps = [t for t in timestamps if now - t < self.window_seconds]
        self._history[session_id] = valid_timestamps

        if len(valid_timestamps) >= self.max_requests:
            return False

        valid_timestamps.append(now)
        self._history[session_id] = valid_timestamps
        return True

    def get_remaining(self, session_id: str) -> int:
        """Get remaining requests in current window."""
        now = time.time()
        timestamps = self._history.get(session_id, [])
        valid_timestamps = [t for t in timestamps if now - t < self.window_seconds]
        return max(0, self.max_requests - len(valid_timestamps))
