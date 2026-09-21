"""
Multi-Architecture Deployment Engines for PyGenGuard.

Supports 4 core enterprise deployment architectures:
1. Simple Gateway Guardrail (Pre-execution inline blocker)
2. Post-Execution Re-Learning & Knowledge Base Filter (Continuous learning data curator)
3. Asynchronous Non-Blocking Security Pipeline (High-throughput async pass)
4. Peak Harness Verification Engine (Data retrieval, validation, and storage)
"""

import time
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Union

from pygenguard.guard import Guard
from pygenguard.output_guard import OutputGuard
from pygenguard.session import Session
from pygenguard.decision import Decision, PlaneResult
from pygenguard.consistency import TruthConsistencyEngine
from pygenguard.harness import DeterministicDataGuard, DataColumnConstraint


# =========================================================================
# Architecture 1: Simple Gateway Guardrail
# =========================================================================

class GatewayGuardrail:
    """Pre-execution inline gateway filter."""

    def __init__(self, guard: Optional[Guard] = None):
        self.guard = guard or Guard()

    def inspect(self, prompt: str, user_id: str = "default_user") -> Decision:
        """Run pre-flight security evaluation before invoking LLM."""
        session = Session(user_id=user_id)
        return self.guard.inspect(prompt, session=session)


# =========================================================================
# Architecture 2: Post-Execution Re-Learning & Dataset Filter
# =========================================================================

@dataclass
class DatasetCurationVerdict:
    """Outcome of dataset review for LLM re-learning or KB ingestion."""
    approved_for_ingestion: bool
    risk_score: float
    reasons: List[str] = field(default_factory=list)
    sanitized_completion: Optional[str] = None
    latency_ms: float = 0.0


class RelearningDatasetFilter:
    """
    Continuous Learning & Knowledge Base Curation Filter.
    
    Inspects model generations before they are ingested into knowledge bases,
    RAG stores, or training/fine-tuning datasets, stripping out toxic completions,
    hallucinated claims, and poisoned backdoors to keep re-learning pure.
    """

    def __init__(
        self,
        output_guard: Optional[OutputGuard] = None,
        truth_engine: Optional[TruthConsistencyEngine] = None,
    ):
        self.output_guard = output_guard or OutputGuard()
        self.truth_engine = truth_engine or TruthConsistencyEngine()

    def review_interaction(
        self,
        prompt: str,
        completion: str,
        reference_ground_truth: Optional[str] = None,
    ) -> DatasetCurationVerdict:
        """Review an interaction pair for re-learning suitability."""
        start_time = time.perf_counter()
        reasons = []

        # 1. Output safety check (PII, secrets, toxicity)
        out_dec = self.output_guard.inspect_output(completion, prompt=prompt)
        if not out_dec.allowed:
            reasons.append(f"Security violation: {out_dec.rationale}")

        # 2. Factuality & contradiction check if ground truth is supplied
        if reference_ground_truth:
            consistency = self.truth_engine.evaluate_consistency(
                completion, reference_context=reference_ground_truth
            )
            if not consistency.passed:
                reasons.extend(consistency.contradictions_detected)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        approved = len(reasons) == 0

        return DatasetCurationVerdict(
            approved_for_ingestion=approved,
            risk_score=0.85 if not approved else 0.05,
            reasons=reasons,
            sanitized_completion=out_dec.sanitized_response or completion if approved else None,
            latency_ms=round(elapsed_ms, 3),
        )


# =========================================================================
# Architecture 3: Asynchronous Non-Blocking Security Pipeline
# =========================================================================

class AsyncSecurityPipeline:
    """Asynchronous pass-through security pipeline for high-concurrency workloads."""

    def __init__(self, guard: Optional[Guard] = None):
        self.guard = guard or Guard()

    async def process_prompt(self, prompt: str, user_id: str = "async_user") -> Decision:
        """Asynchronously inspect a prompt without blocking the main event loop."""
        session = Session(user_id=user_id)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.guard.inspect, prompt, session)

    async def process_batch(self, prompts: List[str]) -> List[Decision]:
        """Concurrently inspect a batch of prompts via asyncio.gather."""
        tasks = [self.process_prompt(p, f"batch_user_{i}") for i, p in enumerate(prompts)]
        return await asyncio.gather(*tasks)


# =========================================================================
# Architecture 4: Peak Harness Engineering Engine
# =========================================================================

class UniversalHarnessEngine:
    """
    Peak Harness Engineering for Data Verification, Retrieval & Storage.
    
    Verifies tabular datasets, structured records, and retrieved context chunks
    with deterministic arithmetic validation (anti-NaN/Inf) and schema enforcement.
    """

    def __init__(self, data_guard: Optional[DeterministicDataGuard] = None):
        self.data_guard = data_guard or DeterministicDataGuard(
            block_on_nan_inf=True,
            block_on_unauthorized_columns=True,
        )

    def verify_and_retrieve(
        self,
        raw_records: List[Dict[str, Any]],
        constraints: Optional[List[DataColumnConstraint]] = None,
        allowed_columns: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Verify data integrity before downstream ingestion or retrieval."""
        res = self.data_guard.validate_records(
            raw_records, constraints=constraints, allowed_columns=allowed_columns
        )
        if not res.passed:
            raise ValueError(f"Harness verification failed: {'; '.join(res.violations)}")
        return raw_records

    def validate_and_store(
        self,
        records: List[Dict[str, Any]],
        target_store: List[Dict[str, Any]],
        constraints: Optional[List[DataColumnConstraint]] = None,
    ) -> bool:
        """Verify records and safely append to destination store."""
        verified = self.verify_and_retrieve(records, constraints=constraints)
        target_store.extend(verified)
        return True
