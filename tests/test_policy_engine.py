"""
Tests for PyGenGuard v1.0 Policy-as-Code Engine.
"""

import json
import pytest
from pygenguard.policy import (
    Policy,
    GuardMode,
    PlanePolicy,
    FailAction,
    RateLimitPolicy,
    ContentSafetyPolicy,
    AuditPolicy,
    AlertPolicy,
)


class TestPolicyEngine:
    def test_default_policy(self):
        policy = Policy.preset("balanced")
        assert policy.name == "balanced"
        assert policy.mode == GuardMode.BALANCED
        assert policy.get_effective_action("intent") == FailAction.BLOCK

    def test_strict_preset(self):
        policy = Policy.preset("strict")
        assert policy.mode == GuardMode.STRICT
        assert policy.content_safety.enabled is True
        assert policy.content_safety.severity_threshold == 0.7
        assert policy.get_plane_policy("intent").timeout_ms == 100.0

    def test_permissive_preset(self):
        policy = Policy.preset("permissive")
        assert policy.mode == GuardMode.PERMISSIVE
        assert policy.content_safety.severity_threshold == 0.7
        assert policy.get_plane_policy("intent").fail_open is False

    def test_shadow_preset(self):
        policy = Policy.preset("shadow")
        assert policy.mode == GuardMode.SHADOW
        assert policy.get_effective_action("intent") == FailAction.LOG_ONLY
        assert policy.get_effective_action("output") == FailAction.LOG_ONLY

    def test_dict_serialization_roundtrip(self):
        policy = Policy.preset("strict")
        d = policy.to_dict()
        restored = Policy.from_dict(d)
        assert restored.name == policy.name
        assert restored.mode == policy.mode
        assert len(restored.planes) == len(policy.planes)
        assert restored.content_safety.enabled == policy.content_safety.enabled

    def test_json_serialization_roundtrip(self):
        policy = Policy.preset("balanced")
        j = policy.to_json(indent=2)
        assert isinstance(j, str)
        restored = Policy.from_json(j)
        assert restored.name == policy.name
        assert restored.mode == GuardMode.BALANCED

    def test_policy_from_file_json(self, tmp_path):
        policy = Policy.preset("strict")
        file_path = str(tmp_path / "test_policy.json")
        policy.save(file_path)

        loaded = Policy.from_file(file_path)
        assert loaded.name == policy.name
        assert loaded.mode == GuardMode.STRICT

    def test_custom_plane_override(self):
        policy = Policy.preset("balanced")
        policy.planes["custom_plane"] = PlanePolicy(
            action_on_fail=FailAction.DEGRADE,
            timeout_ms=50.0,
            fail_open=True,
        )
        assert policy.get_plane_policy("custom_plane").action_on_fail == FailAction.DEGRADE
        assert policy.get_plane_policy("custom_plane").fail_open is True

    def test_missing_plane_fallback(self):
        policy = Policy.preset("balanced")
        fallback = policy.get_plane_policy("non_existent_plane")
        assert fallback.action_on_fail == FailAction.BLOCK
        assert fallback.fail_open is False
