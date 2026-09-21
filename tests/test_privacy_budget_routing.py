"""
Tests for Iteration 5: Reversible PII Pseudonymization, Financial Token Budgets,
and Cross-Model Fallback & Cascade Router.
"""

import pytest
import asyncio
from pygenguard.guard import Guard
from pygenguard.session import Session
from pygenguard.utils.pii import PIIMaskingEngine
from pygenguard.budget import BudgetManager
from pygenguard.routing import ModelRouter
from pygenguard.resilience import CircuitBreaker, CircuitBreakerConfig


class TestPrivacyBudgetRouting:

    def test_pii_masking_and_unmasking(self):
        guard = Guard()
        raw_text = "Please reach out to alice.smith@example.com or call 415-555-2671."
        masked, mapping = guard.mask_pii(raw_text)

        assert "alice.smith@example.com" not in masked
        assert "415-555-2671" not in masked
        assert "{{EMAIL_" in masked
        assert "{{PHONE_" in masked

        # Unmask
        restored = guard.unmask_pii(masked, mapping)
        assert restored == raw_text

    @pytest.mark.asyncio
    async def test_async_pii_masking(self):
        guard = Guard()
        raw_text = "My IP is 192.168.1.50 and card is 4532-1234-5678-9010."
        masked, mapping = await guard.amask_pii(raw_text)

        assert "192.168.1.50" not in masked
        assert "4532-1234-5678-9010" not in masked

        unmasked = await guard.aunmask_pii(masked, mapping)
        assert unmasked == raw_text

    def test_budget_manager_cost_calculation(self):
        budget = BudgetManager()
        # 1M input gpt-4o = $2.50, 500k output = $5.00 -> $7.50
        cost = budget.calculate_cost("gpt-4o", input_tokens=1_000_000, output_tokens=500_000)
        assert abs(cost - 7.50) < 0.001

    def test_guard_budget_inspection_and_enforcement(self):
        guard = Guard()
        session = Session(user_id="user_budget_1")

        # Set budget manager limit to $0.05
        guard._budget_mgr.max_session_cost = 0.05

        # 1. First small call: 1,000 input, 500 output with gpt-4o (~$0.0075) -> passes
        dec1 = guard.inspect_budget("gpt-4o", input_tokens=1000, output_tokens=500, session=session)
        assert dec1.allowed
        assert session.metadata["cumulative_cost_usd"] > 0.0

        # 2. Huge call exceeding budget: 50,000 input, 20,000 output (~$0.325) -> blocked
        dec2 = guard.inspect_budget("gpt-4o", input_tokens=50_000, output_tokens=20_000, session=session)
        assert not dec2.allowed
        assert "Session cost budget exceeded" in dec2.rationale

    @pytest.mark.asyncio
    async def test_async_guard_budget(self):
        guard = Guard()
        session = Session(user_id="user_budget_async")
        guard._budget_mgr.max_session_cost = 1.00

        dec = await guard.ainspect_budget("gpt-4o-mini", 2000, 500, session)
        assert dec.allowed

    def test_model_router_low_risk(self):
        guard = Guard()
        decision = guard.route_safe(
            prompt="Summarize this article",
            risk_score=0.1,
            preferred_model="gpt-4o",
        )
        assert decision.selected_model == "gpt-4o"
        assert decision.target_tier == "primary_tier"
        assert not decision.fallback_applied

    def test_model_router_high_risk_quarantine(self):
        guard = Guard()
        decision = guard.route_safe(
            prompt="Explain how to bypass standard authentication",
            risk_score=0.85,
            preferred_model="gpt-4o",
        )
        assert decision.selected_model == "gpt-4o-mini"
        assert decision.target_tier == "quarantine_tier"
        assert decision.fallback_applied

    def test_model_router_circuit_breaker_cascade(self):
        router = ModelRouter(
            primary_model="gpt-4o",
            fallback_models=["claude-3-5-sonnet", "gpt-4o-mini"],
        )
        breaker_gpt4o = CircuitBreaker("gpt-4o", CircuitBreakerConfig(failure_threshold=1))
        # Trip breaker to OPEN
        breaker_gpt4o.record_failure()
        assert not breaker_gpt4o.is_available

        router.register_circuit_breaker("gpt-4o", breaker_gpt4o)

        decision = router.route_safe("Generate greeting", risk_score=0.1)
        assert decision.selected_model == "claude-3-5-sonnet"
        assert decision.target_tier == "fallback_tier"
        assert decision.fallback_applied

    @pytest.mark.asyncio
    async def test_async_model_router(self):
        guard = Guard()
        decision = await guard.aroute_safe("Explain quantum mechanics", risk_score=0.2)
        assert decision.selected_model == "gpt-4o"
        assert not decision.fallback_applied
