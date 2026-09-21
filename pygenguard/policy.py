"""
Policy-as-Code Engine for PyGenGuard v1.0.

Provides a declarative, composable policy system that replaces hardcoded thresholds
and keyword lists with structured policy definitions loadable from Python dicts,
YAML files, or JSON files.

Supports:
- Hierarchical policy inheritance (base → environment → tenant)
- Per-plane configuration with custom keywords, thresholds, and actions
- Rate limit definitions
- Content safety category configuration
- RBAC role definitions
- Runtime policy hot-reload
"""

import json
import copy
from dataclasses import dataclass, field
from typing import (
    Dict, Optional, List, Any, Literal, Set, Union,
)
from enum import Enum
from pathlib import Path
import os
import asyncio
from typing import Callable


class FailAction(str, Enum):
    """Action to take when a plane check fails."""
    BLOCK = "BLOCK"
    DEGRADE = "DEGRADE"
    CHALLENGE = "CHALLENGE"
    LOG_ONLY = "LOG_ONLY"  # Shadow / canary mode per-plane


class GuardMode(str, Enum):
    """Operating mode for the guard."""
    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"
    SHADOW = "shadow"  # Log-only mode (never blocks)


@dataclass
class PlanePolicy:
    """Configuration for a single security plane."""
    enabled: bool = True
    action_on_fail: FailAction = FailAction.BLOCK
    timeout_ms: float = 100.0  # Max evaluation time before circuit-breaker triggers
    fail_open: bool = False    # If True, plane errors result in ALLOW; if False, BLOCK
    priority: int = 0          # Execution priority (lower = earlier)

    # Plane-specific overrides (passed to plane constructors)
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitPolicy:
    """Rate limiting configuration."""
    enabled: bool = True
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    tokens_per_minute: int = 100_000
    tokens_per_hour: int = 1_000_000
    burst_allowance: float = 1.5  # Multiplier for burst window
    per_user: bool = True
    per_tenant: bool = False


@dataclass
class ContentSafetyPolicy:
    """Content safety category configuration."""
    enabled: bool = True
    block_categories: List[str] = field(default_factory=lambda: [
        "hate_speech", "self_harm", "violence", "sexual_content", "illegal_activity"
    ])
    severity_threshold: float = 0.7  # 0.0-1.0, higher = less strict
    action_on_detect: FailAction = FailAction.BLOCK


@dataclass
class AuditPolicy:
    """Audit and logging configuration."""
    enabled: bool = True
    log_format: Literal["jsonl", "json", "text"] = "jsonl"
    log_destination: Literal["stdout", "file", "both"] = "stdout"
    log_file_path: Optional[str] = None
    log_rotation_mb: int = 100
    include_prompt_text: bool = False  # Privacy: whether to log raw prompt text
    include_plane_details: bool = True
    correlation_id_header: str = "x-request-id"


@dataclass
class AlertPolicy:
    """Alerting and webhook configuration."""
    enabled: bool = False
    webhook_url: Optional[str] = None
    alert_on_actions: List[str] = field(default_factory=lambda: ["BLOCK"])
    alert_on_risk_above: float = 0.8
    rate_limit_alerts_per_minute: int = 10


@dataclass
class Policy:
    """
    Complete policy definition for PyGenGuard.

    Supports construction from:
    - Python dict: Policy.from_dict({...})
    - YAML file:   Policy.from_yaml("policy.yaml")
    - JSON file:   Policy.from_json("policy.json")
    - Presets:     Policy.preset("strict")
    """

    version: str = "1.0"
    name: str = "default"
    mode: GuardMode = GuardMode.BALANCED

    # Per-plane configuration
    planes: Dict[str, PlanePolicy] = field(default_factory=dict)

    # Rate limiting
    rate_limits: RateLimitPolicy = field(default_factory=RateLimitPolicy)

    # Content safety
    content_safety: ContentSafetyPolicy = field(default_factory=ContentSafetyPolicy)

    # Audit settings
    audit: AuditPolicy = field(default_factory=AuditPolicy)

    # Alerting
    alerts: AlertPolicy = field(default_factory=AlertPolicy)

    # Custom metadata (for tenant-specific extensions)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_plane_policy(self, plane_name: str) -> PlanePolicy:
        """Get policy for a specific plane, with defaults if not explicitly configured."""
        if plane_name in self.planes:
            return self.planes[plane_name]
        # Return default plane policy
        return PlanePolicy()

    def is_plane_enabled(self, plane_name: str) -> bool:
        """Check if a plane is enabled in this policy."""
        if self.mode == GuardMode.SHADOW:
            return True  # All planes run in shadow mode (but don't block)
        pp = self.get_plane_policy(plane_name)
        return pp.enabled

    def get_effective_action(self, plane_name: str) -> FailAction:
        """Get the effective action for a plane failure, considering shadow mode."""
        if self.mode == GuardMode.SHADOW:
            return FailAction.LOG_ONLY
        pp = self.get_plane_policy(plane_name)
        return pp.action_on_fail

    def should_fail_open(self, plane_name: str) -> bool:
        """Check if a plane should fail-open on errors."""
        pp = self.get_plane_policy(plane_name)
        return pp.fail_open

    @classmethod
    def preset(cls, mode: str = "balanced") -> "Policy":
        """Create a policy from a named preset."""
        if mode == "strict":
            return cls(
                version="1.0",
                name="strict",
                mode=GuardMode.STRICT,
                planes={
                    "identity": PlanePolicy(config={
                        "trust_thresholds": {"full": 80, "degraded": 50}
                    }),
                    "intent": PlanePolicy(config={
                        "sensitivity": 0.3
                    }),
                    "economics": PlanePolicy(config={
                        "max_burn_rate": 500.0
                    }),
                    "phishing": PlanePolicy(enabled=True),
                    "output": PlanePolicy(config={
                        "block_on_secrets": True,
                        "block_on_dangerous_code": True,
                        "block_on_system_leak": True,
                        "mask_pii": True,
                    }),
                },
                rate_limits=RateLimitPolicy(
                    requests_per_minute=30,
                    tokens_per_minute=50_000
                ),
            )
        elif mode == "permissive":
            return cls(
                version="1.0",
                name="permissive",
                mode=GuardMode.PERMISSIVE,
                planes={
                    "identity": PlanePolicy(config={
                        "trust_thresholds": {"full": 50, "degraded": 20}
                    }),
                    "intent": PlanePolicy(config={
                        "sensitivity": 0.7
                    }),
                    "economics": PlanePolicy(config={
                        "max_burn_rate": 2000.0
                    }),
                },
                rate_limits=RateLimitPolicy(
                    requests_per_minute=120,
                    tokens_per_minute=500_000
                ),
            )
        elif mode == "shadow":
            return cls(
                version="1.0",
                name="shadow",
                mode=GuardMode.SHADOW,
                audit=AuditPolicy(
                    enabled=True,
                    include_prompt_text=True,
                    include_plane_details=True,
                ),
            )
        else:  # balanced
            return cls(
                version="1.0",
                name="balanced",
                mode=GuardMode.BALANCED,
            )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        """
        Construct a Policy from a plain dictionary.

        Example:
            policy = Policy.from_dict({
                "version": "1.0",
                "mode": "strict",
                "planes": {
                    "intent": {"enabled": True, "sensitivity": 0.3}
                },
                "rate_limits": {"requests_per_minute": 30}
            })
        """
        policy = cls()

        policy.version = data.get("version", "1.0")
        policy.name = data.get("name", "custom")

        mode_str = data.get("mode", "balanced")
        try:
            policy.mode = GuardMode(mode_str)
        except ValueError:
            policy.mode = GuardMode.BALANCED

        # Parse planes
        planes_data = data.get("planes", {})
        for plane_name, plane_conf in planes_data.items():
            if isinstance(plane_conf, dict):
                pp = PlanePolicy(
                    enabled=plane_conf.get("enabled", True),
                    timeout_ms=plane_conf.get("timeout_ms", 100.0),
                    fail_open=plane_conf.get("fail_open", False),
                    priority=plane_conf.get("priority", 0),
                )
                action = plane_conf.get("action_on_fail", "BLOCK")
                try:
                    pp.action_on_fail = FailAction(action)
                except ValueError:
                    pp.action_on_fail = FailAction.BLOCK

                # Everything else goes into config
                reserved_keys = {"enabled", "timeout_ms", "fail_open", "priority", "action_on_fail"}
                pp.config = {k: v for k, v in plane_conf.items() if k not in reserved_keys}
                policy.planes[plane_name] = pp

        # Parse rate limits
        rl_data = data.get("rate_limits", {})
        if rl_data:
            policy.rate_limits = RateLimitPolicy(
                enabled=rl_data.get("enabled", True),
                requests_per_minute=rl_data.get("requests_per_minute", 60),
                requests_per_hour=rl_data.get("requests_per_hour", 1000),
                tokens_per_minute=rl_data.get("tokens_per_minute", 100_000),
                tokens_per_hour=rl_data.get("tokens_per_hour", 1_000_000),
                burst_allowance=rl_data.get("burst_allowance", 1.5),
                per_user=rl_data.get("per_user", True),
                per_tenant=rl_data.get("per_tenant", False),
            )

        # Parse content safety
        cs_data = data.get("content_safety", {})
        if cs_data:
            action = cs_data.get("action_on_detect", "BLOCK")
            try:
                cs_action = FailAction(action)
            except ValueError:
                cs_action = FailAction.BLOCK

            policy.content_safety = ContentSafetyPolicy(
                enabled=cs_data.get("enabled", True),
                block_categories=cs_data.get("block_categories", [
                    "hate_speech", "self_harm", "violence", "sexual_content", "illegal_activity"
                ]),
                severity_threshold=cs_data.get("severity_threshold", 0.7),
                action_on_detect=cs_action,
            )

        # Parse audit
        audit_data = data.get("audit", {})
        if audit_data:
            policy.audit = AuditPolicy(
                enabled=audit_data.get("enabled", True),
                log_format=audit_data.get("log_format", "jsonl"),
                log_destination=audit_data.get("log_destination", "stdout"),
                log_file_path=audit_data.get("log_file_path"),
                log_rotation_mb=audit_data.get("log_rotation_mb", 100),
                include_prompt_text=audit_data.get("include_prompt_text", False),
                include_plane_details=audit_data.get("include_plane_details", True),
                correlation_id_header=audit_data.get("correlation_id_header", "x-request-id"),
            )

        # Parse alerts
        alert_data = data.get("alerts", {})
        if alert_data:
            policy.alerts = AlertPolicy(
                enabled=alert_data.get("enabled", False),
                webhook_url=alert_data.get("webhook_url"),
                alert_on_actions=alert_data.get("alert_on_actions", ["BLOCK"]),
                alert_on_risk_above=alert_data.get("alert_on_risk_above", 0.8),
                rate_limit_alerts_per_minute=alert_data.get("rate_limit_alerts_per_minute", 10),
            )

        policy.metadata = data.get("metadata", {})
        return policy

    @classmethod
    def from_json(cls, json_str_or_path: str) -> "Policy":
        """Load a policy from a JSON string or file path."""
        s = json_str_or_path.strip()
        if s.startswith("{") and s.endswith("}"):
            data = json.loads(s)
        else:
            with open(json_str_or_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_yaml(cls, path: str) -> "Policy":
        """Load a policy from a YAML file (requires pyyaml)."""
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML is required for YAML policy files. "
                "Install it with: pip install pygenguard[yaml]"
            )
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        """Load a policy from either a JSON or YAML file based on extension."""
        lower = path.lower()
        if lower.endswith(".yaml") or lower.endswith(".yml"):
            return cls.from_yaml(path)
        return cls.from_json(path)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the policy to a plain dictionary."""
        d: Dict[str, Any] = {
            "version": self.version,
            "name": self.name,
            "mode": self.mode.value,
            "planes": {},
            "rate_limits": {
                "enabled": self.rate_limits.enabled,
                "requests_per_minute": self.rate_limits.requests_per_minute,
                "requests_per_hour": self.rate_limits.requests_per_hour,
                "tokens_per_minute": self.rate_limits.tokens_per_minute,
                "tokens_per_hour": self.rate_limits.tokens_per_hour,
                "burst_allowance": self.rate_limits.burst_allowance,
                "per_user": self.rate_limits.per_user,
                "per_tenant": self.rate_limits.per_tenant,
            },
            "content_safety": {
                "enabled": self.content_safety.enabled,
                "block_categories": self.content_safety.block_categories,
                "severity_threshold": self.content_safety.severity_threshold,
                "action_on_detect": self.content_safety.action_on_detect.value,
            },
            "audit": {
                "enabled": self.audit.enabled,
                "log_format": self.audit.log_format,
                "log_destination": self.audit.log_destination,
                "log_file_path": self.audit.log_file_path,
                "include_prompt_text": self.audit.include_prompt_text,
                "include_plane_details": self.audit.include_plane_details,
            },
        }

        for pname, pp in self.planes.items():
            plane_dict: Dict[str, Any] = {
                "enabled": pp.enabled,
                "action_on_fail": pp.action_on_fail.value,
                "timeout_ms": pp.timeout_ms,
                "fail_open": pp.fail_open,
            }
            plane_dict.update(pp.config)
            d["planes"][pname] = plane_dict

        if self.metadata:
            d["metadata"] = self.metadata

        return d

    def to_json(self, path: Optional[str] = None, indent: int = 2) -> Optional[str]:
        """Save the policy to a JSON file, or return JSON string if path is None."""
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=indent)
            return None
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str, indent: int = 2) -> None:
        """Save the policy to a file."""
        self.to_json(path=path, indent=indent)

    def merge(self, override: "Policy") -> "Policy":
        """
        Create a new policy by merging this policy with an override.
        Override values take precedence. Useful for tenant-specific overrides.
        """
        base_dict = self.to_dict()
        override_dict = override.to_dict()

        def deep_merge(base: dict, over: dict) -> dict:
            merged = copy.deepcopy(base)
            for k, v in over.items():
                if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
                    merged[k] = deep_merge(merged[k], v)
                else:
                    merged[k] = copy.deepcopy(v)
            return merged

        merged_dict = deep_merge(base_dict, override_dict)
        return Policy.from_dict(merged_dict)

    def validate(self) -> List[str]:
        """
        Validate the policy for logical consistency.
        Returns a list of warning/error messages (empty = valid).
        """
        issues: List[str] = []

        if self.rate_limits.enabled:
            if self.rate_limits.requests_per_minute <= 0:
                issues.append("rate_limits.requests_per_minute must be > 0")
            if self.rate_limits.tokens_per_minute <= 0:
                issues.append("rate_limits.tokens_per_minute must be > 0")

        for pname, pp in self.planes.items():
            if pp.timeout_ms <= 0:
                issues.append(f"planes.{pname}.timeout_ms must be > 0")
            if pp.timeout_ms > 5000:
                issues.append(f"planes.{pname}.timeout_ms ({pp.timeout_ms}ms) is very high — may impact latency")

        if self.content_safety.enabled:
            if not (0.0 <= self.content_safety.severity_threshold <= 1.0):
                issues.append("content_safety.severity_threshold must be between 0.0 and 1.0")

        return issues


class PolicyWatcher:
    """
    Watches a policy file on disk for changes and triggers reload callbacks.

    Usage:
        watcher = PolicyWatcher("security_policy.json", on_reload=guard.reload_policy)
        # Check manually or run background async watcher:
        new_pol = watcher.check_for_reload()
    """

    def __init__(self, policy_path: str, on_reload: Optional[Callable[[Policy], None]] = None):
        self.path = Path(policy_path)
        self.on_reload = on_reload
        self._last_mtime: float = self.path.stat().st_mtime if self.path.exists() else 0.0
        self._running: bool = False

    def check_for_reload(self) -> Optional[Policy]:
        """Check if policy file modified synchronously and reload if changed."""
        if not self.path.exists():
            return None
        current_mtime = self.path.stat().st_mtime
        if current_mtime > self._last_mtime:
            self._last_mtime = current_mtime
            new_policy = Policy.from_file(str(self.path))
            if self.on_reload:
                self.on_reload(new_policy)
            return new_policy
        return None

    async def awatch(self, poll_interval_sec: float = 0.5) -> None:
        """Asynchronously watch for file modifications in a background loop."""
        self._running = True
        while self._running:
            await asyncio.sleep(poll_interval_sec)
            self.check_for_reload()

    def stop(self) -> None:
        """Stop background file watcher."""
        self._running = False
