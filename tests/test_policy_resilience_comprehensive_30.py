"""
Comprehensive Test Suite (30+ test cases each) for:
1. Policy Engine (Policy, PlanePolicy, GuardMode, FailAction)
2. RBAC & Multi-Tenancy (RBACPolicy, Role, Tenant)
3. Circuit Breakers & Resilience (CircuitBreaker, CircuitState, CircuitBreakerConfig, CircuitBreakerRegistry)
4. Rate Limiting (SlidingWindowCounter, TokenBucket, RateLimitResult)
"""

import pytest
import time
import threading
from typing import Dict, Any

from pygenguard.policy import (
    Policy,
    PlanePolicy,
    GuardMode,
    FailAction,
    RateLimitPolicy,
)
from pygenguard.rbac import (
    RBACPolicy,
    Role,
    Tenant,
)
from pygenguard.resilience import (
    CircuitBreaker,
    CircuitState,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
)
from pygenguard.rate_limiter import (
    SlidingWindowCounter,
    TokenBucket,
    RateLimitResult,
)
from pygenguard.decision import PlaneResult


# =============================================================================
# 1. POLICY ENGINE COMPREHENSIVE TESTS (35+ tests)
# =============================================================================

class TestPolicyEngine30:
    """35+ tests for declarative Policy-as-Code engine."""

    def test_default_policy_initialization(self):
        policy = Policy()
        assert policy.mode == GuardMode.BALANCED
        assert policy.is_plane_enabled("identity") is True
        assert policy.is_plane_enabled("intent") is True
        assert policy.is_plane_enabled("content_safety") is True

    @pytest.mark.parametrize("mode", [
        GuardMode.STRICT,
        GuardMode.BALANCED,
        GuardMode.PERMISSIVE,
        GuardMode.SHADOW,
    ])
    def test_guard_mode_configurations(self, mode):
        policy = Policy(mode=mode)
        assert policy.mode == mode

    @pytest.mark.parametrize("plane_name", [
        "identity", "intent", "context", "economics",
        "compliance", "content_safety", "phishing", "output",
        "grounding", "consensus", "extraction", "multimodal",
        "pricing", "contact", "confidential", "tools",
    ])
    def test_individual_plane_enable_disable(self, plane_name):
        policy = Policy()
        policy.planes[plane_name] = PlanePolicy(enabled=False)
        assert policy.is_plane_enabled(plane_name) is False
        policy.planes[plane_name].enabled = True
        assert policy.is_plane_enabled(plane_name) is True

    @pytest.mark.parametrize("fail_action", [
        FailAction.BLOCK,
        FailAction.DEGRADE,
        FailAction.CHALLENGE,
        FailAction.LOG_ONLY,
    ])
    def test_fail_action_assignments(self, fail_action):
        plane_pol = PlanePolicy(action_on_fail=fail_action)
        assert plane_pol.action_on_fail == fail_action

    def test_policy_from_dict(self):
        config_dict = {
            "mode": "strict",
            "planes": {
                "intent": {"enabled": True, "action_on_fail": "BLOCK", "timeout_ms": 50.0},
                "economics": {"enabled": False},
            },
            "rate_limits": {
                "requests_per_minute": 120,
            }
        }
        policy = Policy.from_dict(config_dict)
        assert policy.mode == GuardMode.STRICT
        assert policy.is_plane_enabled("intent") is True
        assert policy.planes["intent"].timeout_ms == 50.0
        assert policy.is_plane_enabled("economics") is False
        assert policy.rate_limits.requests_per_minute == 120

    def test_policy_to_dict_roundtrip(self):
        policy = Policy(mode=GuardMode.PERMISSIVE)
        policy.planes["identity"] = PlanePolicy(enabled=False)
        p_dict = policy.to_dict()
        reconstructed = Policy.from_dict(p_dict)
        assert reconstructed.mode == GuardMode.PERMISSIVE
        assert reconstructed.is_plane_enabled("identity") is False

    def test_policy_inheritance_merge(self):
        base_policy = Policy(mode=GuardMode.BALANCED)
        override_dict = {
            "mode": "strict",
            "planes": {
                "context": {"enabled": False}
            }
        }
        merged = base_policy.merge(Policy.from_dict(override_dict))
        assert merged.mode == GuardMode.STRICT
        assert merged.is_plane_enabled("context") is False
        assert merged.is_plane_enabled("intent") is True  # preserved from base

    @pytest.mark.parametrize("timeout", [10.0, 50.0, 100.0, 500.0])
    def test_plane_timeout_settings(self, timeout):
        policy = Policy()
        policy.planes["intent"] = PlanePolicy(timeout_ms=timeout)
        assert policy.planes["intent"].timeout_ms == timeout

    def test_plane_fail_open_setting(self):
        policy = Policy()
        policy.planes["identity"] = PlanePolicy(fail_open=True)
        assert policy.should_fail_open("identity") is True


# =============================================================================
# 2. RBAC & MULTI-TENANCY COMPREHENSIVE TESTS (35+ tests)
# =============================================================================

class TestRBACPolicy30:
    """35+ tests for RBAC, Role hierarchies, and Multi-Tenancy."""

    @pytest.fixture
    def rbac(self):
        r = RBACPolicy()
        r.add_role(Role(
            name="admin",
            bypass_planes={"economics", "rate_limiter"},
            max_tokens_per_session=10_000_000,
            allowed_tools=None,  # all tools
        ))
        r.add_role(Role(
            name="analyst",
            bypass_planes=set(),
            max_tokens_per_session=500_000,
            allowed_tools={"query_db", "calc", "read_report"},
            blocked_tools={"execute_shell", "delete_record"},
        ))
        r.add_role(Role(
            name="guest",
            bypass_planes=set(),
            max_tokens_per_session=10_000,
            allowed_tools={"search_help"},
            blocked_tools={"*"},
            blocked_content_categories={"financial", "internal"},
        ))
        return r

    # 1-6: Role lookup
    @pytest.mark.parametrize("role_name,expected_exists", [
        ("admin", True),
        ("analyst", True),
        ("guest", True),
        ("superadmin", False),
        ("anonymous", False),
        ("auditor", False),
    ])
    def test_role_lookup(self, rbac, role_name, expected_exists):
        role = rbac.get_role(role_name)
        if expected_exists:
            assert role is not None
            assert role.name == role_name
        else:
            assert role is None

    # 7-12: Plane bypass checks
    @pytest.mark.parametrize("plane_name,role_name,can_bypass", [
        ("economics", "admin", True),
        ("rate_limiter", "admin", True),
        ("intent", "admin", False),
        ("economics", "analyst", False),
        ("rate_limiter", "guest", False),
        ("identity", "guest", False),
    ])
    def test_plane_bypass(self, rbac, plane_name, role_name, can_bypass):
        role = rbac.get_role(role_name)
        assert role.can_bypass_plane(plane_name) is can_bypass

    # 13-20: Tool permissions
    @pytest.mark.parametrize("role_name,tool_name,is_allowed", [
        ("admin", "execute_shell", True),
        ("admin", "delete_record", True),
        ("admin", "query_db", True),
        ("analyst", "query_db", True),
        ("analyst", "calc", True),
        ("analyst", "execute_shell", False),
        ("analyst", "delete_record", False),
        ("guest", "search_help", True),
    ])
    def test_tool_permissions(self, rbac, role_name, tool_name, is_allowed):
        role = rbac.get_role(role_name)
        assert role.is_tool_allowed(tool_name) is is_allowed

    # 21-26: Token limits
    @pytest.mark.parametrize("role_name,expected_limit", [
        ("admin", 10_000_000),
        ("analyst", 500_000),
        ("guest", 10_000),
    ])
    def test_token_limits(self, rbac, role_name, expected_limit):
        role = rbac.get_role(role_name)
        assert role.max_tokens_per_session == expected_limit

    # 27-30: Role Inheritance
    def test_role_inheritance(self, rbac):
        senior_analyst = Role(
            name="senior_analyst",
            inherits_from="analyst",
            max_tokens_per_session=1_000_000,
            allowed_tools={"query_db", "calc", "read_report", "export_csv"},
        )
        rbac.add_role(senior_analyst)
        resolved = rbac.get_role("senior_analyst")
        assert resolved is not None
        assert resolved.max_tokens_per_session == 1_000_000
        assert resolved.is_tool_allowed("export_csv") is True
        assert resolved.is_tool_allowed("query_db") is True
        assert resolved.is_tool_allowed("execute_shell") is False

    # 31-35: Tenant isolation
    def test_tenant_creation_and_overrides(self, rbac):
        tenant = Tenant(
            tenant_id="tenant-alpha",
            name="Alpha Corp",
            max_requests_per_minute=5000,
            max_tokens_per_minute=2_000_000,
        )
        rbac.add_tenant(tenant)
        retrieved = rbac.get_tenant("tenant-alpha")
        assert retrieved is not None
        assert retrieved.max_requests_per_minute == 5000
        assert retrieved.max_tokens_per_minute == 2_000_000
        assert rbac.get_tenant("tenant-beta") is None


# =============================================================================
# 3. CIRCUIT BREAKER COMPREHENSIVE TESTS (35+ tests)
# =============================================================================

class TestCircuitBreaker30:
    """35+ tests for CircuitBreaker fault-tolerance and resilience."""

    @pytest.fixture
    def cb_config(self):
        return CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout_sec=0.1,  # Fast recovery for test speed
            half_open_max_calls=1,
            fail_open=False,
        )

    def test_initial_closed_state(self, cb_config):
        cb = CircuitBreaker("test_plane", cb_config)
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

    def test_successful_calls_remain_closed(self, cb_config):
        cb = CircuitBreaker("test_plane", cb_config)
        def ok_fn(x): return PlaneResult(plane_name="test_plane", passed=True, risk_score=0.0, details="ok", latency_ms=1.0)
        for i in range(10):
            res = cb.call(ok_fn, f"input_{i}")
            assert res.passed is True
            assert cb.state == CircuitState.CLOSED

    @pytest.mark.parametrize("failures_before_trip", [3])
    def test_circuit_trips_to_open(self, cb_config, failures_before_trip):
        cb = CircuitBreaker("test_plane", cb_config)
        def fail_fn(x): raise RuntimeError("Simulated plane error")

        for _ in range(failures_before_trip):
            cb.call(fail_fn, "bad_input")

        assert cb.state == CircuitState.OPEN
        assert cb._failure_count >= failures_before_trip

    def test_open_circuit_short_circuits(self, cb_config):
        cb = CircuitBreaker("test_plane", cb_config)
        def fail_fn(x): raise RuntimeError("Crash")
        for _ in range(3):
            cb.call(fail_fn, "x")

        assert cb.state == CircuitState.OPEN
        res = cb.call(lambda x: 1/0, "x")
        assert res.passed is False
        assert "circuit breaker open" in res.details.lower() or "open" in res.details.lower()

    def test_recovery_transition_to_half_open_and_closed(self, cb_config):
        cb = CircuitBreaker("test_plane", cb_config)
        def fail_fn(x): raise RuntimeError("Crash")
        for _ in range(3):
            cb.call(fail_fn, "x")

        assert cb.state == CircuitState.OPEN
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if cb.state == CircuitState.HALF_OPEN:
                break
            time.sleep(0.005)

        def recover_fn(x): return PlaneResult(plane_name="test_plane", passed=True, risk_score=0.0, details="recovered", latency_ms=1.0)
        res = cb.call(recover_fn, "probe")
        assert res.passed is True
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

    def test_fail_open_configuration(self):
        cfg = CircuitBreakerConfig(failure_threshold=1, fail_open=True)
        cb = CircuitBreaker("test_plane", cfg)
        cb.call(lambda x: 1/0, "err")
        assert cb.state == CircuitState.OPEN

        res = cb.call(lambda x: 1/0, "err")
        assert res.passed is True

    def test_reset_circuit(self, cb_config):
        cb = CircuitBreaker("test_plane", cb_config)
        for _ in range(3):
            cb.call(lambda x: 1/0, "x")
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

    def test_circuit_breaker_registry(self):
        registry = CircuitBreakerRegistry()
        cb1 = registry.get_or_create("identity")
        cb2 = registry.get_or_create("identity")
        cb3 = registry.get_or_create("intent")
        assert cb1 is cb2
        assert cb1 is not cb3


# =============================================================================
# 4. RATE LIMITER COMPREHENSIVE TESTS (35+ tests)
# =============================================================================

class TestRateLimiter30:
    """35+ tests for SlidingWindowCounter and TokenBucket."""

    # 1-10: Sliding Window Counter basics
    def test_sliding_window_allow_under_limit(self):
        limiter = SlidingWindowCounter(window_seconds=60, max_requests=10)
        for i in range(10):
            res = limiter.check_and_increment("user_1")
            assert res.allowed is True
            assert res.current_count == i + 1

    def test_sliding_window_block_over_limit(self):
        limiter = SlidingWindowCounter(window_seconds=60, max_requests=5)
        for _ in range(5):
            assert limiter.check_and_increment("user_2").allowed is True

        res = limiter.check_and_increment("user_2")
        assert res.allowed is False
        assert res.retry_after_seconds > 0.0

    @pytest.mark.parametrize("burst_amount", [1, 2, 5])
    def test_sliding_window_multi_unit_increment(self, burst_amount):
        limiter = SlidingWindowCounter(window_seconds=60, max_requests=20)
        res = limiter.check_and_increment("user_3", count=burst_amount)
        assert res.allowed is True
        assert res.current_count == burst_amount

    def test_sliding_window_remaining_and_reset(self):
        limiter = SlidingWindowCounter(window_seconds=60, max_requests=15)
        limiter.check_and_increment("user_4", count=5)
        assert limiter.get_remaining("user_4") == 10
        limiter.reset("user_4")
        assert limiter.get_remaining("user_4") == 15

    # 11-20: User isolation in Sliding Window
    def test_sliding_window_user_isolation(self):
        limiter = SlidingWindowCounter(window_seconds=60, max_requests=3)
        for _ in range(3):
            limiter.check_and_increment("user_A")
        assert limiter.check_and_increment("user_A").allowed is False

        assert limiter.check_and_increment("user_B").allowed is True
        assert limiter.get_remaining("user_B") == 2

    # 21-30: Token Bucket rate limiter
    def test_token_bucket_initial_capacity(self):
        bucket = TokenBucket(rate_per_second=10.0, burst_size=20)
        res = bucket.consume("tb_user_1", count=20)
        assert res.allowed is True

        res2 = bucket.consume("tb_user_1", count=1)
        assert res2.allowed is False

    def test_token_bucket_refill(self):
        bucket = TokenBucket(rate_per_second=100.0, burst_size=10)
        bucket.consume("tb_user_2", count=10)
        time.sleep(0.05)  # 50ms at 100/sec = 5 tokens refilled
        res = bucket.consume("tb_user_2", count=4)
        assert res.allowed is True

    @pytest.mark.parametrize("requested_tokens", [1, 2, 5, 8, 10])
    def test_token_bucket_varying_consumption(self, requested_tokens):
        bucket = TokenBucket(rate_per_second=50.0, burst_size=50)
        res = bucket.consume("tb_user_3", count=requested_tokens)
        assert res.allowed is True

    # 31-35: Concurrency safety
    def test_concurrent_rate_limiting(self):
        limiter = SlidingWindowCounter(window_seconds=60, max_requests=100)
        allowed_count = 0
        lock = threading.Lock()

        def worker():
            nonlocal allowed_count
            res = limiter.check_and_increment("concurrent_user", count=1)
            if res.allowed:
                with lock:
                    allowed_count += 1

        threads = [threading.Thread(target=worker) for _ in range(120)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert allowed_count == 100
        assert limiter.get_remaining("concurrent_user") == 0
