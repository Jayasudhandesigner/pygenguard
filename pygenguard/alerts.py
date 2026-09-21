"""
Alerting & Webhook System for PyGenGuard v1.0.

Provides:
- Webhook notifications for security events
- Rate-limited alert dispatching
- Configurable alert triggers (BLOCK, high risk, circuit breaker trips)
- Pluggable alert backends (webhook, log, custom)
"""

import json
import time
import threading
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Callable


class AlertBackend(ABC):
    """Base class for alert delivery backends."""

    @abstractmethod
    def send(self, alert: Dict[str, Any]) -> bool:
        """Send an alert. Returns True on success."""
        ...


class WebhookAlert(AlertBackend):
    """
    Send alerts via HTTP webhook (Slack, Discord, PagerDuty, custom).

    Usage:
        webhook = WebhookAlert("https://hooks.slack.com/services/T.../B.../xxx")
    """

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout_seconds: float = 5.0,
        transform: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout_seconds
        self.transform = transform

    def send(self, alert: Dict[str, Any]) -> bool:
        """Send alert via HTTP POST."""
        try:
            payload = self.transform(alert) if self.transform else alert
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers=self.headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status < 400
        except Exception:
            return False


class LogAlert(AlertBackend):
    """Write alerts to a dedicated alert log file."""

    def __init__(self, log_file: str = "pygenguard_alerts.jsonl"):
        self.log_file = log_file

    def send(self, alert: Dict[str, Any]) -> bool:
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, separators=(',', ':')) + "\n")
            return True
        except Exception:
            return False


class CallbackAlert(AlertBackend):
    """Call a user-provided callback function with the alert."""

    def __init__(self, callback: Callable[[Dict[str, Any]], None]):
        self.callback = callback

    def send(self, alert: Dict[str, Any]) -> bool:
        try:
            self.callback(alert)
            return True
        except Exception:
            return False


class AlertManager:
    """
    Manages alert dispatching with rate limiting and configurable triggers.

    Usage:
        alerts = AlertManager(
            backends=[
                WebhookAlert("https://hooks.slack.com/..."),
                LogAlert("alerts.jsonl"),
            ],
            alert_on_actions=["BLOCK"],
            alert_on_risk_above=0.8,
            max_alerts_per_minute=10,
        )

        # Called automatically by Guard on each decision
        alerts.process_decision(decision, user_id="user_123")
    """

    def __init__(
        self,
        backends: Optional[List[AlertBackend]] = None,
        alert_on_actions: Optional[List[str]] = None,
        alert_on_risk_above: float = 0.8,
        max_alerts_per_minute: int = 10,
        enabled: bool = True,
    ):
        self.backends = backends or []
        self.alert_on_actions = set(alert_on_actions or ["BLOCK"])
        self.alert_on_risk_above = alert_on_risk_above
        self.max_alerts_per_minute = max_alerts_per_minute
        self.enabled = enabled

        self._alert_timestamps: List[float] = []
        self._lock = threading.Lock()
        self._total_sent = 0
        self._total_suppressed = 0

    def _is_rate_limited(self) -> bool:
        """Check if we've exceeded the alert rate limit."""
        now = time.monotonic()
        with self._lock:
            # Remove timestamps older than 60 seconds
            self._alert_timestamps = [
                t for t in self._alert_timestamps if now - t < 60
            ]
            return len(self._alert_timestamps) >= self.max_alerts_per_minute

    def _record_alert(self) -> None:
        """Record that an alert was sent."""
        with self._lock:
            self._alert_timestamps.append(time.monotonic())
            self._total_sent += 1

    def should_alert(self, decision: Any) -> bool:
        """Determine if a decision warrants an alert."""
        if not self.enabled:
            return False

        # Check action trigger
        if decision.action in self.alert_on_actions:
            return True

        # Check risk score trigger
        if decision.combined_risk_score >= self.alert_on_risk_above:
            return True

        return False

    def process_decision(
        self,
        decision: Any,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Process a decision and dispatch alerts if warranted.

        Args:
            decision: Decision object
            user_id: User identifier
            agent_id: Agent identifier
            correlation_id: Request correlation ID
            extra: Additional metadata

        Returns:
            True if alert was sent, False if suppressed or not warranted
        """
        if not self.should_alert(decision):
            return False

        if self._is_rate_limited():
            with self._lock:
                self._total_suppressed += 1
            return False

        alert_payload = self._build_alert(
            decision, user_id, agent_id, correlation_id, extra
        )

        # Dispatch to all backends (fire-and-forget in background)
        success = False
        for backend in self.backends:
            try:
                if backend.send(alert_payload):
                    success = True
            except Exception:
                continue

        if success:
            self._record_alert()

        return success

    def _build_alert(
        self,
        decision: Any,
        user_id: Optional[str],
        agent_id: Optional[str],
        correlation_id: Optional[str],
        extra: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build the alert payload."""
        alert: Dict[str, Any] = {
            "alert_type": "security_event",
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "severity": self._get_severity(decision),
            "trace_id": decision.trace_id,
            "action": decision.action,
            "allowed": decision.allowed,
            "risk_score": decision.combined_risk_score,
            "rationale": decision.rationale,
        }

        if user_id:
            alert["user_id"] = user_id
        if agent_id:
            alert["agent_id"] = agent_id
        if correlation_id:
            alert["correlation_id"] = correlation_id

        # Plane summary (just names and pass/fail, not full details)
        alert["plane_summary"] = {
            name: {"passed": pr.passed, "risk": pr.risk_score}
            for name, pr in decision.plane_results.items()
        }

        if extra:
            alert["metadata"] = extra

        return alert

    @staticmethod
    def _get_severity(decision: Any) -> str:
        """Determine alert severity from decision."""
        if decision.combined_risk_score >= 0.9:
            return "critical"
        elif decision.combined_risk_score >= 0.7:
            return "high"
        elif decision.combined_risk_score >= 0.5:
            return "medium"
        return "low"

    def send_custom_alert(
        self,
        alert_type: str,
        message: str,
        severity: str = "info",
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send a custom alert (e.g., circuit breaker trip, policy reload)."""
        if not self.enabled or self._is_rate_limited():
            return False

        alert: Dict[str, Any] = {
            "alert_type": alert_type,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "severity": severity,
            "message": message,
        }
        if details:
            alert.update(details)

        success = False
        for backend in self.backends:
            try:
                if backend.send(alert):
                    success = True
            except Exception:
                continue

        if success:
            self._record_alert()
        return success

    def get_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        return {
            "total_sent": self._total_sent,
            "total_suppressed": self._total_suppressed,
            "backends_count": len(self.backends),
            "enabled": self.enabled,
        }
