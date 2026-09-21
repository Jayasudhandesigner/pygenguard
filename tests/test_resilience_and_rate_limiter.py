"""
Tests for PyGenGuard v1.0 Resilience, Circuit Breakers, and Rate Limiter.
"""

import time
import pytest
from pygenguard.resilience import (
    CircuitBreaker,
    CircuitState,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
)
from pygenguard.rate_limiter import (
    RateLimiter,
    RateLimitResult,
    SlidingWindowCounter,
    TokenBucket,
)
from pygenguard.decision import PlaneResult


class TestCircuitBreaker:
    def test_normal_operation_closed_state(self):
        cb = CircuitBreaker("test_cb", CircuitBreakerConfig(failure_threshold=3))
        assert cb.state == CircuitState.CLOSED

        result = cb.call(lambda x: PlaneResult(plane_name="test", passed=True, risk_score=0.0, details=f"val_{x}"), 21)
        assert result.passed is True
        assert cb.state == CircuitState.CLOSED

    def test_trip_to_open_after_failures(self):
        cb = CircuitBreaker(
            "flaky_service",
            CircuitBreakerConfig(failure_threshold=2, recovery_timeout_sec=0.1, fail_open=False),
        )

        def failing_func():
            raise ValueError("Service unavailable")

        # 1st failure
        res1 = cb.call(failing_func)
        assert isinstance(res1, PlaneResult)
        assert not res1.passed
        assert cb.state == CircuitState.CLOSED

        # 2nd failure -> trips circuit breaker
        res2 = cb.call(failing_func)
        assert not res2.passed
        assert cb.state == CircuitState.OPEN

        # Subsequent call when OPEN fails immediately without calling target
        res3 = cb.call(lambda: PlaneResult(plane_name="flaky", passed=True, risk_score=0.0, details="never"))
        assert not res3.passed
        assert "OPEN" in res3.details

    def test_fail_open_behavior(self):
        cb = CircuitBreaker(
            "optional_plane",
            CircuitBreakerConfig(failure_threshold=1, fail_open=True),
        )
        res = cb.call(lambda: (_ for _ in ()).throw(RuntimeError("error")))
        # With fail_open=True, result should pass with warning
        assert res.passed is True
        assert res.risk_score == 0.0

    def test_half_open_recovery(self):
        cb = CircuitBreaker(
            "recoverable_cb",
            CircuitBreakerConfig(failure_threshold=1, recovery_timeout_sec=0.05),
        )
        # Fail once to open
        cb.call(lambda: (_ for _ in ()).throw(Exception("down")))
        assert cb.state == CircuitState.OPEN

        time.sleep(0.06)  # wait for recovery timeout

        # Successful call transitions through HALF_OPEN back to CLOSED
        res = cb.call(lambda: PlaneResult(plane_name="rec", passed=True, risk_score=0.0, details="ok"))
        assert res.passed is True
        assert cb.state == CircuitState.CLOSED

    def test_registry(self):
        registry = CircuitBreakerRegistry(CircuitBreakerConfig(failure_threshold=5))
        cb1 = registry.get_or_create("plane_a")
        cb2 = registry.get_or_create("plane_a")
        assert cb1 is cb2
        health = registry.get_all_health()
        assert "plane_a" in health
        assert health["plane_a"]["state"] == "closed"


class TestRateLimiter:
    def test_allow_within_limit(self):
        rl = RateLimiter(requests_per_minute=10, burst_multiplier=1.0)
        res = rl.check_request(key="user_1")
        assert res.passed is True
        assert res.risk_score == 0.0

    def test_throttle_exceeded_requests(self):
        rl = RateLimiter(requests_per_minute=3, burst_multiplier=1.0)
        user = "spammer"
        for _ in range(3):
            assert rl.check_request(user).passed is True

        # 4th request exceeds rate limit
        res = rl.check_request(user)
        assert res.passed is False
        assert res.risk_score > 0.5
        assert "rate limit" in res.details.lower() or "burst" in res.details.lower()

    def test_token_rate_limiting(self):
        rl = RateLimiter(tokens_per_minute=500, burst_multiplier=2.0)
        # 1st request with 300 tokens: allowed
        res1 = rl.check_request("user_tokens", token_count=300)
        assert res1.passed is True

        # 2nd request with 300 tokens: exceeds 500 limit
        res2 = rl.check_request("user_tokens", token_count=300)
        assert res2.passed is False
        assert "tpm" in res2.details.lower() or "limit" in res2.details.lower()

    def test_rate_limiter_reset(self):
        rl = RateLimiter(requests_per_minute=1, burst_multiplier=1.0)
        rl.check_request("user_x")
        assert rl.check_request("user_x").passed is False
        rl.reset("user_x")
        assert rl.check_request("user_x").passed is True
