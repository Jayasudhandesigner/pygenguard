"""
Tests for PyGenGuard v1.0 Alerting & Webhooks.
"""

import pytest
from pygenguard.alerts import (
    AlertManager,
    CallbackAlert,
    LogAlert,
    WebhookAlert,
)
from pygenguard.decision import Decision, PlaneResult


class TestAlerting:
    def test_callback_alert_dispatch(self):
        received_alerts = []

        def on_alert(alert):
            received_alerts.append(alert)

        callback_backend = CallbackAlert(callback=on_alert)
        manager = AlertManager(
            backends=[callback_backend],
            alert_on_actions=["BLOCK"],
            max_alerts_per_minute=10,
        )

        decision = Decision.create_block(
            trace_id="tr_123",
            plane_results={"intent": PlaneResult(plane_name="intent", passed=False, risk_score=0.9, details="Injection")},
            rationale="Intent check failed: Prompt injection detected",
        )

        assert manager.should_alert(decision) is True
        sent = manager.process_decision(decision, user_id="test_user")
        assert sent is True
        assert len(received_alerts) == 1
        assert received_alerts[0]["action"] == "BLOCK"
        assert received_alerts[0]["trace_id"] == "tr_123"

    def test_alert_suppression_on_allow(self):
        received = []
        backend = CallbackAlert(callback=lambda a: received.append(a))
        manager = AlertManager(backends=[backend], alert_on_actions=["BLOCK"])

        decision = Decision.create_allow(
            trace_id="tr_ok",
            plane_results={},
            rationale="Passed",
        )
        assert manager.should_alert(decision) is False
        manager.process_decision(decision)
        assert len(received) == 0

    def test_alert_rate_limiting(self):
        received = []
        backend = CallbackAlert(callback=lambda a: received.append(a))
        manager = AlertManager(
            backends=[backend],
            alert_on_actions=["BLOCK"],
            max_alerts_per_minute=2,
        )

        dec = Decision.create_block(trace_id="1", plane_results={}, rationale="block")
        # 1st alert: sent
        assert manager.process_decision(dec) is True
        # 2nd alert: sent
        assert manager.process_decision(dec) is True
        # 3rd alert: rate limited / suppressed
        assert manager.process_decision(dec) is False
        assert len(received) == 2

    def test_log_alert_backend(self, tmp_path):
        log_file = str(tmp_path / "alerts.jsonl")
        log_backend = LogAlert(log_file=log_file)
        success = log_backend.send({"event": "test_alert", "risk": 0.95})
        assert success is True

        with open(log_file, "r", encoding="utf-8") as f:
            content = f.read()
            assert "test_alert" in content
