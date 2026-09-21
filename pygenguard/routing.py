"""
Cross-Model Safe Routing and Fallback Cascade Engine for PyGenGuard.

Routes requests across model tiers based on risk scores, circuit breaker status,
cost constraints, and fallback cascades. Ensures resilient, secure AI operations
by automatically downgrading or isolating suspicious or failing model calls.
"""

import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from pygenguard.resilience import CircuitBreaker, CircuitState


@dataclass
class RouteDecision:
    """Represents the chosen route and reasoning for model execution."""
    selected_model: str
    target_tier: str
    reason: str
    risk_score: float
    fallback_applied: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class ModelRouter:
    """
    Intelligent routing engine with safety downgrade and circuit-breaker cascades.

    Usage:
        router = ModelRouter(
            primary_model="gpt-4o",
            fallback_models=["claude-3-5-sonnet", "gpt-4o-mini"],
            high_risk_model="gpt-4o-mini",
            risk_threshold=0.6,
        )
        decision = router.route_safe(prompt="Hello", risk_score=0.1)
        # decision.selected_model == "gpt-4o"

        # If risk is elevated:
        decision = router.route_safe(prompt="Suspicious prompt", risk_score=0.75)
        # decision.selected_model == "gpt-4o-mini" (routed to isolated sandbox/cheaper tier)
    """

    def __init__(
        self,
        primary_model: str = "gpt-4o",
        fallback_models: Optional[List[str]] = None,
        high_risk_model: str = "gpt-4o-mini",
        risk_threshold: float = 0.6,
        circuit_breakers: Optional[Dict[str, CircuitBreaker]] = None,
    ):
        self.primary_model = primary_model
        self.fallback_models = fallback_models or ["gpt-4o-mini", "claude-3-haiku"]
        self.high_risk_model = high_risk_model
        self.risk_threshold = risk_threshold
        self.circuit_breakers = circuit_breakers or {}

    def register_circuit_breaker(self, model: str, breaker: CircuitBreaker) -> None:
        """Associate a circuit breaker with a specific model name."""
        self.circuit_breakers[model] = breaker

    def route_safe(
        self,
        prompt: str,
        risk_score: float = 0.0,
        preferred_model: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RouteDecision:
        """
        Evaluate risk score, breaker status, and determine the safest model destination.
        """
        meta = metadata or {}
        # 1. Check if high-risk threshold is exceeded
        if risk_score >= self.risk_threshold:
            return RouteDecision(
                selected_model=self.high_risk_model,
                target_tier="quarantine_tier",
                reason=f"Risk score {risk_score:.2f} >= threshold {self.risk_threshold:.2f}; routed to containment tier.",
                risk_score=risk_score,
                fallback_applied=True,
                metadata=meta,
            )

        # 2. Check candidate model (preferred or primary)
        candidate = preferred_model or self.primary_model

        # 3. Check circuit breaker status for candidate
        breaker = self.circuit_breakers.get(candidate)
        if breaker and (breaker.state == CircuitState.OPEN or str(breaker.state).lower() == "open"):
            # Candidate is down, cascade through fallbacks
            for fallback in self.fallback_models:
                fb_breaker = self.circuit_breakers.get(fallback)
                if not fb_breaker or (fb_breaker.state != CircuitState.OPEN and str(fb_breaker.state).lower() != "open"):
                    return RouteDecision(
                        selected_model=fallback,
                        target_tier="fallback_tier",
                        reason=f"Primary model '{candidate}' circuit breaker is OPEN; cascading to '{fallback}'.",
                        risk_score=risk_score,
                        fallback_applied=True,
                        metadata=meta,
                    )
            # All fallbacks open
            return RouteDecision(
                selected_model=self.high_risk_model,
                target_tier="emergency_tier",
                reason=f"All configured model circuit breakers OPEN; routing to emergency fallback '{self.high_risk_model}'.",
                risk_score=risk_score,
                fallback_applied=True,
                metadata=meta,
            )

        # 4. Standard route approved
        return RouteDecision(
            selected_model=candidate,
            target_tier="primary_tier",
            reason="Primary model operational and risk within approved bounds.",
            risk_score=risk_score,
            fallback_applied=False,
            metadata=meta,
        )

    async def aroute_safe(
        self,
        prompt: str,
        risk_score: float = 0.0,
        preferred_model: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RouteDecision:
        """Asynchronously evaluate risk score and determine the safest model destination."""
        return self.route_safe(
            prompt=prompt,
            risk_score=risk_score,
            preferred_model=preferred_model,
            metadata=metadata,
        )
