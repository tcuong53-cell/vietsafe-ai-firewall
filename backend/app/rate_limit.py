import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Depends, HTTPException, status

from .config import Settings, get_settings
from .security import Principal, require_scope


@dataclass
class Bucket:
    timestamps: deque[float]


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, Bucket] = defaultdict(lambda: Bucket(deque()))

    def check(self, key: str, limit: int, window_seconds: int = 60) -> None:
        now = time.monotonic()
        bucket = self._buckets[key].timestamps
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
        bucket.append(now)


limiter = InMemoryRateLimiter()


def rate_limited_principal(
    principal: Principal = Depends(require_scope("inspect")),
    settings: Settings = Depends(get_settings),
) -> Principal:
    limiter.check(principal.api_key.id, settings.rate_limit_per_minute)
    return principal
