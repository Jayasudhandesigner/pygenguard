"""
Asynchronous BYOK & Jev Confidence Decider for PyGenGuard.

Enables customers to leverage their own API keys (OpenAI, Anthropic, Gemini, Azure, Jev)
as an asynchronous second-opinion decider for borderline or high-stakes guardrail evaluations.
"""

import time
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Literal, Union, Tuple

from pygenguard.decision import PlaneResult
from pygenguard.byok.judge import BYOKConfig, JudgeVerdict, BYOKLLMJudge
from pygenguard.jev.client import AsyncJevClient, JevClient
from pygenguard.jev.schemas import JevPreExecutionVerdict, JevPostExecutionVerdict
from pygenguard.optimization import BYOKExecutionVault


@dataclass
class BYOKConfidenceVerdict:
    """Standardized decision outcome from the Async BYOK Confidence Decider."""
    allowed: bool
    confidence: float
    risk_score: float
    reasoning: str
    decider_type: str  # "jev_fast_path", "byok_llm_judge", "hybrid_consensus"
    latency_ms: float
    flagged_categories: List[str] = field(default_factory=list)
    provider_used: str = "local"
    masked_key: str = "NOT_CONFIGURED"
    requires_escalation: bool = False

    def to_plane_result(self, plane_name: str = "byok_confidence_decider") -> PlaneResult:
        """Convert to standard PyGenGuard PlaneResult for pipeline integration."""
        return PlaneResult(
            plane_name=plane_name,
            passed=self.allowed,
            risk_score=self.risk_score,
            details=f"[{self.decider_type.upper()}|{self.provider_used}] {self.reasoning} (conf={self.confidence:.2f})",
            latency_ms=self.latency_ms,
        )


class AsyncBYOKConfidenceDecider:
    """
    Asynchronous confidence decider combining Jev System One tokenless evaluation
    with customer-supplied BYOK LLM models for high-fidelity security decisions.

    Features:
    - Zero-leakage local credential handling via BYOKExecutionVault.
    - Tiered evaluation: sub-millisecond Jev fast-path first.
    - Dynamic confidence thresholding: automatically invokes BYOK LLM judge only if
      confidence is ambiguous (within uncertainty_range) or when force_byok_llm is set.
    - Fully async native (asyncio / await).
    - Multi-provider support: OpenAI, Anthropic, Gemini, Azure, Custom vLLM, and Jev.
    """

    def __init__(
        self,
        vault: Optional[BYOKExecutionVault] = None,
        config: Optional[BYOKConfig] = None,
        uncertainty_range: Tuple[float, float] = (0.35, 0.75),
        prefer_jev_tokenless: bool = True,
        jev_client: Optional[AsyncJevClient] = None,
        llm_judge: Optional[BYOKLLMJudge] = None,
    ):
        self.vault = vault or BYOKExecutionVault()
        self.config = config or BYOKConfig()
        self.uncertainty_range = uncertainty_range
        self.prefer_jev_tokenless = prefer_jev_tokenless
        self.jev_client = jev_client or AsyncJevClient()
        self.llm_judge = llm_judge or BYOKLLMJudge(config=self.config)

    async def decide(
        self,
        text: str,
        context: Optional[str] = None,
        force_byok_llm: bool = False,
        threshold: float = 0.5,
    ) -> BYOKConfidenceVerdict:
        """
        Evaluate input text and return a high-confidence security verdict.
        Runs tokenless Jev fast-path first; escalates to BYOK LLM judge if confidence is borderline.
        """
        start_time = time.perf_counter()

        # Step 1: Execute Jev Tokenless System One Fast-Path
        jev_verdict: JevPreExecutionVerdict = await self.jev_client.evaluate_pre_execution(text)
        jev_risk = jev_verdict.risk_score
        is_uncertain = self.uncertainty_range[0] <= jev_risk <= self.uncertainty_range[1]

        # If clean or blatant attack with high certainty, and not forced to invoke BYOK LLM
        if not force_byok_llm and not is_uncertain:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return BYOKConfidenceVerdict(
                allowed=not jev_verdict.is_malicious,
                confidence=round(1.0 - jev_risk if not jev_verdict.is_malicious else jev_risk, 3),
                risk_score=round(jev_risk, 3),
                reasoning=jev_verdict.reasoning,
                decider_type="jev_fast_path",
                latency_ms=round(elapsed_ms, 3),
                flagged_categories=[str(jev_verdict.threat_category)] if jev_verdict.is_malicious else [],
                provider_used="jev_tokenless",
                masked_key="LOCAL_TOKENLESS",
                requires_escalation=False,
            )

        # Step 2: Escalate to Customer BYOK LLM Judge
        provider = self.config.provider
        masked_key = self.vault.get_masked_key(provider) if self.vault.has_key(provider) else "NOT_CONFIGURED"

        judge_verdict: JudgeVerdict = await self.llm_judge.aevaluate(text, context)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # If LLM Judge failed or was unconfigured, fall back gracefully to Jev verdict
        if "judge_failure" in judge_verdict.flagged_categories or "unconfigured_byok" in judge_verdict.flagged_categories:
            return BYOKConfidenceVerdict(
                allowed=not jev_verdict.is_malicious,
                confidence=0.60,
                risk_score=round(jev_risk, 3),
                reasoning=f"BYOK fallback to Jev: {judge_verdict.reasoning}",
                decider_type="jev_fast_path_fallback",
                latency_ms=round(elapsed_ms, 3),
                flagged_categories=[str(jev_verdict.threat_category)] if jev_verdict.is_malicious else [],
                provider_used="jev_fallback",
                masked_key=masked_key,
                requires_escalation=True,
            )

        # Consensus between Jev and BYOK LLM Judge
        consensus_allowed = judge_verdict.allowed and (not jev_verdict.is_malicious if jev_risk > 0.7 else True)
        combined_confidence = round((judge_verdict.confidence * 0.7) + ((1.0 - jev_risk if consensus_allowed else jev_risk) * 0.3), 3)
        combined_risk = round(1.0 - combined_confidence if consensus_allowed else combined_confidence, 3)

        return BYOKConfidenceVerdict(
            allowed=consensus_allowed,
            confidence=combined_confidence,
            risk_score=combined_risk,
            reasoning=judge_verdict.reasoning,
            decider_type="byok_llm_judge",
            latency_ms=round(elapsed_ms, 3),
            flagged_categories=judge_verdict.flagged_categories,
            provider_used=judge_verdict.provider_used,
            masked_key=masked_key,
            requires_escalation=not consensus_allowed,
        )


class BYOKConfidenceDecider:
    """
    Synchronous wrapper for AsyncBYOKConfidenceDecider.
    Provides identical API for synchronous pipelines.
    """

    def __init__(self, async_decider: Optional[AsyncBYOKConfidenceDecider] = None, **kwargs):
        self._async_decider = async_decider or AsyncBYOKConfidenceDecider(**kwargs)

    def decide(
        self,
        text: str,
        context: Optional[str] = None,
        force_byok_llm: bool = False,
        threshold: float = 0.5,
    ) -> BYOKConfidenceVerdict:
        """Synchronously evaluate text using the underlying async decider."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(
                    lambda: asyncio.run(self._async_decider.decide(text, context, force_byok_llm, threshold))
                ).result()

        return loop.run_until_complete(
            self._async_decider.decide(text, context, force_byok_llm, threshold)
        )
