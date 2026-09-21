"""
Resilience Module for PyGenGuard v1.0.

Provides:
- Circuit Breaker pattern for plane evaluation fault tolerance
- Configurable fail-open / fail-closed behavior
- Timeout enforcement for individual plane evaluations
- Health tracking and recovery for degraded planes
"""

import time
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Any, Optional, Dict
from pygenguard.decision import PlaneResult


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"        # Normal operation — all calls pass through
    OPEN = "open"            # Tripped — calls are short-circuited
    HALF_OPEN = "half_open"  # Recovery probe — single call allowed through


@dataclass
class CircuitBreakerConfig:
    """Configuration for a single circuit breaker."""
    failure_threshold: int = 5          # Consecutive failures to trip
    recovery_timeout_sec: float = 30.0  # Seconds before attempting recovery
    half_open_max_calls: int = 1        # Calls allowed in half-open state
    fail_open: bool = False             # True = ALLOW on trip; False = BLOCK


class CircuitBreaker:
    """
    Circuit breaker for a single security plane.

    States:
    - CLOSED: Normal operation, calls pass through
    - OPEN: Tripped after threshold failures, all calls short-circuited
    - HALF_OPEN: Recovery probe, limited calls allowed

    Usage:
        cb = CircuitBreaker("intent", config)
        result = cb.call(plane.evaluate, prompt)
    """

    def __init__(self, plane_name: str, config: Optional[CircuitBreakerConfig] = None):
        self.plane_name = plane_name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._half_open_calls = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Current circuit state (with auto-transition from OPEN → HALF_OPEN)."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.config.recovery_timeout_sec:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
            return self._state

    @property
    def is_available(self) -> bool:
        """Check if the circuit allows calls."""
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            with self._lock:
                return self._half_open_calls < self.config.half_open_max_calls
        return False  # OPEN

    def record_success(self) -> None:
        """Record a successful call — resets failure count, closes circuit."""
        with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """Record a failed call — may trip the circuit."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                # Failed during recovery probe — re-open
                self._state = CircuitState.OPEN
            elif self._failure_count >= self.config.failure_threshold:
                self._state = CircuitState.OPEN

    def call(
        self,
        func: Callable[..., PlaneResult],
        *args: Any,
        timeout_ms: float = 100.0,
        **kwargs: Any
    ) -> PlaneResult:
        """
        Execute a plane evaluation through the circuit breaker.

        Args:
            func: Plane evaluation function
            *args: Arguments to pass to the function
            timeout_ms: Maximum execution time in milliseconds
            **kwargs: Keyword arguments to pass to the function

        Returns:
            PlaneResult from the plane, or a synthetic result if circuit is open

        Raises:
            Nothing — all exceptions are caught and converted to PlaneResults
        """
        if not self.is_available:
            # Circuit is OPEN — short-circuit
            return PlaneResult(
                plane_name=self.plane_name,
                passed=self.config.fail_open,
                risk_score=0.0 if self.config.fail_open else 1.0,
                details=f"Circuit breaker OPEN for {self.plane_name} — "
                        f"{'fail-open (ALLOW)' if self.config.fail_open else 'fail-closed (BLOCK)'}",
                latency_ms=0.0,
            )

        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_calls += 1

        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000

            # Check for timeout
            if elapsed_ms > timeout_ms:
                self.record_failure()
                return PlaneResult(
                    plane_name=self.plane_name,
                    passed=self.config.fail_open,
                    risk_score=0.5,
                    details=f"{self.plane_name} evaluation timed out ({elapsed_ms:.1f}ms > {timeout_ms}ms)",
                    latency_ms=elapsed_ms,
                )

            self.record_success()
            return result

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.record_failure()
            return PlaneResult(
                plane_name=self.plane_name,
                passed=self.config.fail_open,
                risk_score=0.0 if self.config.fail_open else 1.0,
                details=f"{self.plane_name} evaluation error: {type(exc).__name__}: {exc}",
                latency_ms=elapsed_ms,
            )

    def reset(self) -> None:
        """Reset the circuit breaker to closed state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_calls = 0

    def get_health(self) -> Dict[str, Any]:
        """Get circuit breaker health status."""
        state = self.state
        return {
            "plane": self.plane_name,
            "state": state.value,
            "failure_count": self._failure_count,
            "is_available": self.is_available,
            "fail_open": self.config.fail_open,
        }


class CircuitBreakerRegistry:
    """
    Registry of circuit breakers for all planes.

    Usage:
        registry = CircuitBreakerRegistry()
        cb = registry.get_or_create("intent")
        result = cb.call(intent_plane.evaluate, prompt)
    """

    def __init__(self, default_config: Optional[CircuitBreakerConfig] = None):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._default_config = default_config or CircuitBreakerConfig()
        self._lock = threading.Lock()

    def get_or_create(
        self,
        plane_name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get or create a circuit breaker for a plane."""
        with self._lock:
            if plane_name not in self._breakers:
                cfg = config or self._default_config
                self._breakers[plane_name] = CircuitBreaker(plane_name, cfg)
            return self._breakers[plane_name]

    def get_all_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all circuit breakers."""
        with self._lock:
            return {name: cb.get_health() for name, cb in self._breakers.items()}

    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        with self._lock:
            for cb in self._breakers.values():
                cb.reset()
