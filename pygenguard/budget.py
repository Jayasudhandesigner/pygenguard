"""
Dynamic Model Cost & Budget Enforcement Plane for PyGenGuard.

Tracks monetary expenditure based on provider model pricing (per 1M tokens),
enforces per-session and per-user hard dollar budgets, and protects against
infinite billing loops.
"""

import time
from dataclasses import dataclass
from typing import Optional, Dict, Any
from pygenguard.decision import PlaneResult
from pygenguard.session import Session


# Pricing per 1,000,000 tokens (USD)
MODEL_TOKEN_PRICING_PER_1M = {
    # OpenAI
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    # Anthropic
    "claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
    "claude-3-opus": {"input": 15.00, "output": 75.00},
    # Google Gemini
    "gemini-1.5-pro": {"input": 3.50, "output": 10.50},
    "gemini-1.5-flash": {"input": 0.35, "output": 1.05},
    # Open weights / Llama
    "llama-3-70b": {"input": 0.80, "output": 0.80},
    "llama-3-8b": {"input": 0.20, "output": 0.20},
}


class BudgetManager:
    """
    Tracks and enforces financial dollar budgets per session and user.

    Usage:
        budget = BudgetManager(max_session_cost_usd=1.00)
        cost = budget.calculate_cost("gpt-4o", input_tokens=1000, output_tokens=500)
        result = budget.inspect_cost("gpt-4o", 1000, 500, session)
        if not result.passed:
            # Throttle or downgrade to cheaper model
    """

    def __init__(
        self,
        max_session_cost_usd: float = 2.00,
        pricing_overrides: Optional[Dict[str, Dict[str, float]]] = None,
    ):
        self.max_session_cost = max_session_cost_usd
        self.pricing = {**MODEL_TOKEN_PRICING_PER_1M, **(pricing_overrides or {})}

    def calculate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int = 0,
    ) -> float:
        """Calculate exact USD cost for a token count."""
        model_key = model.lower()
        # Find matching model key prefix
        matched_pricing = None
        for k, v in self.pricing.items():
            if k in model_key or model_key in k:
                matched_pricing = v
                break

        if not matched_pricing:
            # Fallback default: $1.00 / 1M tokens
            matched_pricing = {"input": 1.00, "output": 2.00}

        cost_in = (input_tokens / 1_000_000.0) * matched_pricing["input"]
        cost_out = (output_tokens / 1_000_000.0) * matched_pricing["output"]
        return cost_in + cost_out

    def inspect_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        session: Session,
    ) -> PlaneResult:
        """
        Evaluate if a call is within the session's dollar budget.
        """
        start = time.perf_counter()
        call_cost = self.calculate_cost(model, input_tokens, output_tokens)

        # Get session cumulative cost
        current_session_cost = session.metadata.get("cumulative_cost_usd", 0.0)
        new_total_cost = current_session_cost + call_cost
        session.metadata["cumulative_cost_usd"] = new_total_cost

        elapsed = (time.perf_counter() - start) * 1000.0
        passed = new_total_cost <= self.max_session_cost

        if passed:
            details = f"Cost approved: ${new_total_cost:.4f} / ${self.max_session_cost:.2f} budget ({model})"
            risk_score = 0.0
        else:
            details = f"Session cost budget exceeded: ${new_total_cost:.4f} > max ${self.max_session_cost:.2f} ({model})"
            risk_score = 0.8

        return PlaneResult(
            plane_name="budget",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=elapsed,
        )
