"""
Hybrid Inspection Engine for PyGenGuard.

Combines high-speed Zero-LLM deterministic defense planes with conditional,
uncertainty-triggered BYOK (Bring Your Own Key) LLM-as-a-Judge fallbacks.

Ensures 95%+ of traffic experiences <2ms zero-token overhead, while ambiguous
and borderline risk scores trigger deep semantic second-opinion evaluations.
"""

import uuid
import time
import asyncio
from dataclasses import dataclass
from typing import Optional, Dict, Any

from pygenguard.session import Session
from pygenguard.decision import Decision, PlaneResult
from pygenguard.byok.judge import BYOKConfig, JudgeVerdict, BYOKLLMJudge


@dataclass
class HybridDecision:
    """Detailed decision including deterministic verdict and optional BYOK judge trail."""
    decision: Decision
    used_llm_judge: bool = False
    judge_verdict: Optional[JudgeVerdict] = None
    confidence_zone: str = "high_confidence_deterministic"  # "high_confidence", "ambiguous_fallback", "deterministic_only"


class HybridGuardEngine:
    """
    Hybrid coordinator orchestrating deterministic fast-planes and conditional BYOK judge.

    Usage:
        hybrid = HybridGuardEngine(guard, byok_config=BYOKConfig(provider="openai", api_key="sk-..."))
        res = hybrid.inspect_hybrid("Some borderline query", session=session)
        if res.used_llm_judge:
            print("Evaluated with BYOK Second Opinion:", res.judge_verdict.reasoning)
    """

    def __init__(
        self,
        guard: Any,
        byok_config: Optional[BYOKConfig] = None,
        uncertainty_min: float = 0.35,
        uncertainty_max: float = 0.70,
    ):
        self.guard = guard
        self.byok_config = byok_config
        self.byok_judge = BYOKLLMJudge(byok_config) if byok_config else None
        self.uncertainty_min = uncertainty_min
        self.uncertainty_max = uncertainty_max

    def set_byok_config(self, config: BYOKConfig) -> None:
        """Update active BYOK judge configuration."""
        self.byok_config = config
        self.byok_judge = BYOKLLMJudge(config)

    def inspect_hybrid(
        self,
        prompt: str,
        session: Optional[Session] = None,
        context: Optional[str] = None,
        byok_config_override: Optional[BYOKConfig] = None,
    ) -> HybridDecision:
        """
        Execute deterministic fast-path inspection with conditional BYOK second-opinion fallback.
        """
        start = time.perf_counter()
        effective_session = session or Session.create("hybrid_session")
        
        # 1. Deterministic Fast-Plane Evaluation (<2ms)
        det_decision = self.guard.inspect(prompt, effective_session)
        risk = det_decision.combined_risk_score

        # Determine active judge instance
        active_judge = BYOKLLMJudge(byok_config_override) if byok_config_override else self.byok_judge

        # 2. Check if risk falls in ambiguous uncertainty zone
        is_ambiguous = (self.uncertainty_min <= risk <= self.uncertainty_max) or (not det_decision.allowed and risk < 0.60)
        
        if is_ambiguous and active_judge and active_judge.config.api_key:
            # 3. Trigger BYOK LLM-as-a-Judge Fallback
            verdict = active_judge.evaluate(prompt, context=context)
            trace_id = det_decision.trace_id or str(uuid.uuid4())
            
            judge_plane_result = PlaneResult(
                plane_name="byok_llm_judge",
                passed=verdict.allowed,
                risk_score=1.0 - verdict.confidence if verdict.allowed else verdict.confidence,
                details=f"[{verdict.provider_used}] {verdict.reasoning}",
                latency_ms=verdict.latency_ms,
            )
            
            merged_plane_results = {**det_decision.plane_results, "byok_judge": judge_plane_result}

            if verdict.allowed:
                final_decision = Decision.create_allow(
                    trace_id=trace_id,
                    plane_results=merged_plane_results,
                    rationale=f"Deterministic risk {risk:.2f} resolved by BYOK LLM Judge: {verdict.reasoning}",
                    sanitized_response=det_decision.sanitized_response,
                )
            else:
                final_decision = Decision.create_block(
                    trace_id=trace_id,
                    plane_results=merged_plane_results,
                    rationale=f"BYOK LLM Judge confirmed violation: {verdict.reasoning} (flags: {verdict.flagged_categories})",
                    safe_response="Request flagged by secondary security intelligence.",
                )

            return HybridDecision(
                decision=final_decision,
                used_llm_judge=True,
                judge_verdict=verdict,
                confidence_zone="ambiguous_resolved_by_judge",
            )

        # 4. Return zero-LLM deterministic verdict directly
        return HybridDecision(
            decision=det_decision,
            used_llm_judge=False,
            judge_verdict=None,
            confidence_zone="high_confidence_deterministic",
        )

    async def ainspect_hybrid(
        self,
        prompt: str,
        session: Optional[Session] = None,
        context: Optional[str] = None,
        byok_config_override: Optional[BYOKConfig] = None,
    ) -> HybridDecision:
        """Asynchronously execute hybrid deterministic + BYOK judge evaluation."""
        return await asyncio.to_thread(
            self.inspect_hybrid,
            prompt,
            session,
            context,
            byok_config_override,
        )
