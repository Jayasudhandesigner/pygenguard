"""
Comprehensive Integration Tests for PyGenGuard v0.3.0.
"""

import pytest
import asyncio
from pygenguard import Guard, AsyncGuard, Session, OutputGuard, BasePlane, PlaneConfig, PlanePhase, PlaneResult
from pygenguard.metrics import get_metrics_collector


class CustomOutputSignaturePlane(BasePlane):
    """Custom output plugin that checks for mandatory security watermark."""
    
    @classmethod
    def get_config(cls) -> PlaneConfig:
        return PlaneConfig(
            name="security_watermark",
            phase=PlanePhase.POST_OUTPUT,
            priority=10
        )
        
    def evaluate(self, prompt, session, context=None) -> PlaneResult:
        # prompt here contains output_text during POST_OUTPUT phase
        return PlaneResult(
            plane_name="security_watermark",
            passed=True,
            risk_score=0.0,
            details="Watermark verified",
            latency_ms=0.05
        )


@pytest.mark.asyncio
async def test_full_roundtrip_async_guard_with_output_and_metrics():
    """Full end-to-end roundtrip testing input, output, plugins, and metrics."""
    guard = AsyncGuard(mode="balanced")
    guard.register_plugin(CustomOutputSignaturePlane)
    collector = get_metrics_collector()
    
    session = Session.create(
        user_id="enterprise_user_99",
        ip_address="192.168.10.50",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    
    # 1. Inspect Prompt
    user_prompt = "Can you help me summarize our Q3 enterprise security posture?"
    in_decision = await guard.inspect(user_prompt, session)
    assert in_decision.allowed is True
    assert in_decision.action == "ALLOW"
    collector.record_decision(in_decision)
    
    # 2. Simulate Model Output with sensitive PII that gets sanitized
    raw_model_response = (
        "Here is the summary. The lead auditor was contact@auditor.com and their "
        "verification code was SSN 987-65-4321."
    )
    
    out_decision = await guard.inspect_output(
        output_text=raw_model_response,
        prompt=user_prompt,
        session=session
    )
    
    assert out_decision.allowed is True
    assert "security_watermark" in out_decision.plane_results
    assert out_decision.plane_results["security_watermark"].passed is True
    
    # Verify PII was redacted
    sanitized = out_decision.sanitized_response
    assert "987-65-4321" not in sanitized
    assert "[REDACTED_SSN]" in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    
    collector.record_decision(out_decision)
    
    # Verify Prometheus metrics recorded both
    prom_data = collector.generate_prometheus_text()
    assert "pygenguard_inspections_total" in prom_data
    
    guard.close()
