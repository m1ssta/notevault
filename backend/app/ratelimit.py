import time
from collections import defaultdict, deque


class RateLimiter:
    """Sliding-window limiter, in memory (single instance). SR-7."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        t = time.monotonic()
        q = self.hits[key]
        while q and t - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(t)
        return True
