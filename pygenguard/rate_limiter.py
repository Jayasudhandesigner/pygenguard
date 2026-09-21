"""
Rate Limiter for PyGenGuard v1.0.

Provides:
- Sliding window rate limiting per user / per tenant / per API key
- Token bucket algorithm for burst allowance
- Thread-safe in-memory implementation
- Redis-backed distributed rate limiting (optional)
- Configurable limits: requests/min, tokens/min, cost/hour
"""

import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any
from pygenguard.decision import PlaneResult


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    current_count: int
    limit: int
    window_seconds: int
    retry_after_seconds: float = 0.0
    reason: str = ""


class SlidingWindowCounter:
    """
    Sliding window rate limiter using a simple time-bucketed counter.

    Thread-safe implementation suitable for single-process deployments.
    For distributed deployments, use RedisRateLimiter.
    """

    def __init__(self, window_seconds: int = 60, max_requests: int = 60):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self._counts: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def _cleanup(self, key: str, now: float) -> None:
        """Remove expired entries."""
        cutoff = now - self.window_seconds
        self._counts[key] = [t for t in self._counts[key] if t > cutoff]

    def check_and_increment(self, key: str, count: int = 1) -> RateLimitResult:
        """
        Check if the request is within rate limits and record it.

        Args:
            key: Identifier (user_id, tenant_id, api_key)
            count: Number of units to record (1 for requests, token_count for tokens)

        Returns:
            RateLimitResult with allowed status
        """
        now = time.monotonic()

        with self._lock:
            self._cleanup(key, now)
            current = len(self._counts[key])

            if current + count > self.max_requests:
                # Calculate retry-after
                if self._counts[key]:
                    oldest = min(self._counts[key])
                    retry_after = oldest + self.window_seconds - now
                else:
                    retry_after = self.window_seconds

                return RateLimitResult(
                    allowed=False,
                    current_count=current,
                    limit=self.max_requests,
                    window_seconds=self.window_seconds,
                    retry_after_seconds=max(0.0, retry_after),
                    reason=f"Rate limit exceeded: {current}/{self.max_requests} per {self.window_seconds}s",
                )

            # Record the request
            for _ in range(count):
                self._counts[key].append(now)

            return RateLimitResult(
                allowed=True,
                current_count=current + count,
                limit=self.max_requests,
                window_seconds=self.window_seconds,
            )

    def get_remaining(self, key: str) -> int:
        """Get remaining requests in the current window."""
        now = time.monotonic()
        with self._lock:
            self._cleanup(key, now)
            return max(0, self.max_requests - len(self._counts[key]))

    def reset(self, key: Optional[str] = None) -> None:
        """Reset counters for a key or all keys."""
        with self._lock:
            if key:
                self._counts.pop(key, None)
            else:
                self._counts.clear()


class TokenBucket:
    """
    Token bucket rate limiter for burst-tolerant rate limiting.

    Allows short bursts above the steady-state rate while enforcing
    a long-term average rate.
    """

    def __init__(
        self,
        rate_per_second: float,
        burst_size: int,
    ):
        self.rate = rate_per_second
        self.burst_size = burst_size
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_refill)
        self._lock = threading.Lock()

    def _refill(self, key: str, now: float) -> float:
        """Refill tokens based on elapsed time."""
        if key not in self._buckets:
            self._buckets[key] = (float(self.burst_size), now)
            return float(self.burst_size)

        tokens, last_refill = self._buckets[key]
        elapsed = now - last_refill
        new_tokens = min(self.burst_size, tokens + elapsed * self.rate)
        self._buckets[key] = (new_tokens, now)
        return new_tokens

    def consume(self, key: str, count: int = 1) -> RateLimitResult:
        """
        Try to consume tokens from the bucket.

        Args:
            key: Identifier
            count: Tokens to consume

        Returns:
            RateLimitResult
        """
        now = time.monotonic()

        with self._lock:
            available = self._refill(key, now)

            if available >= count:
                self._buckets[key] = (available - count, now)
                return RateLimitResult(
                    allowed=True,
                    current_count=int(self.burst_size - (available - count)),
                    limit=self.burst_size,
                    window_seconds=int(self.burst_size / max(0.001, self.rate)),
                )
            else:
                wait_time = (count - available) / max(0.001, self.rate)
                return RateLimitResult(
                    allowed=False,
                    current_count=int(self.burst_size - available),
                    limit=self.burst_size,
                    window_seconds=int(self.burst_size / max(0.001, self.rate)),
                    retry_after_seconds=wait_time,
                    reason=f"Token bucket exhausted: {available:.0f}/{self.burst_size} available",
                )

    def reset(self, key: Optional[str] = None) -> None:
        """Reset bucket(s)."""
        with self._lock:
            if key:
                self._buckets.pop(key, None)
            else:
                self._buckets.clear()


class RateLimiter:
    """
    Composite rate limiter combining sliding window and token bucket algorithms.

    Enforces:
    - Requests per minute (sliding window)
    - Requests per hour (sliding window)
    - Tokens per minute (sliding window)
    - Burst allowance (token bucket)

    Usage:
        limiter = RateLimiter(
            requests_per_minute=60,
            tokens_per_minute=100_000,
        )
        result = limiter.check_request("user_123")
        if not result.passed:
            return rate_limit_response(result)
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        tokens_per_minute: int = 100_000,
        tokens_per_hour: int = 1_000_000,
        burst_multiplier: float = 1.5,
    ):
        self._req_per_min = SlidingWindowCounter(
            window_seconds=60, max_requests=requests_per_minute
        )
        self._req_per_hour = SlidingWindowCounter(
            window_seconds=3600, max_requests=requests_per_hour
        )
        self._tok_per_min = SlidingWindowCounter(
            window_seconds=60, max_requests=tokens_per_minute
        )
        self._tok_per_hour = SlidingWindowCounter(
            window_seconds=3600, max_requests=tokens_per_hour
        )
        self._burst_bucket = TokenBucket(
            rate_per_second=requests_per_minute / 60.0,
            burst_size=int(requests_per_minute * burst_multiplier),
        )

    def check_request(self, key: str, token_count: int = 0) -> PlaneResult:
        """
        Check all rate limits for a request.

        Args:
            key: User/tenant identifier
            token_count: Estimated token count for the request

        Returns:
            PlaneResult with pass/fail status
        """
        start = time.perf_counter()
        violations = []

        # 1. Burst check (token bucket)
        burst_result = self._burst_bucket.consume(key)
        if not burst_result.allowed:
            violations.append(f"Burst limit: {burst_result.reason}")

        # 2. Requests per minute
        rpm_result = self._req_per_min.check_and_increment(key)
        if not rpm_result.allowed:
            violations.append(f"RPM limit: {rpm_result.reason}")

        # 3. Requests per hour
        rph_result = self._req_per_hour.check_and_increment(key)
        if not rph_result.allowed:
            violations.append(f"RPH limit: {rph_result.reason}")

        # 4. Token limits (if token_count provided)
        if token_count > 0:
            tpm_result = self._tok_per_min.check_and_increment(key, token_count)
            if not tpm_result.allowed:
                violations.append(f"TPM limit: {tpm_result.reason}")

            tph_result = self._tok_per_hour.check_and_increment(key, token_count)
            if not tph_result.allowed:
                violations.append(f"TPH limit: {tph_result.reason}")

        passed = len(violations) == 0
        details = "; ".join(violations) if violations else "Within rate limits"
        risk_score = min(1.0, len(violations) * 0.4) if violations else 0.0

        return PlaneResult(
            plane_name="rate_limiter",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def get_remaining(self, key: str) -> Dict[str, int]:
        """Get remaining capacity across all limit types."""
        return {
            "requests_per_minute": self._req_per_min.get_remaining(key),
            "requests_per_hour": self._req_per_hour.get_remaining(key),
        }

    def reset(self, key: Optional[str] = None) -> None:
        """Reset all rate limiters."""
        self._req_per_min.reset(key)
        self._req_per_hour.reset(key)
        self._tok_per_min.reset(key)
        self._tok_per_hour.reset(key)
        self._burst_bucket.reset(key)
