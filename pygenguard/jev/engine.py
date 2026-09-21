"""
Dual-Layer Governance Engine for PyGenGuard.

Coordinates:
1. Pre-Execution Blocking (Frontend Threat Mitigation)
2. Post-Execution KB Filtering (Backend Dataset Cleansing & Anti-Poisoning)
3. Asynchronous Scaling with AsyncJevClient & Background Worker
"""

import time
import uuid
import asyncio
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Union

from pygenguard.session import Session
from pygenguard.decision import Decision, PlaneResult
from pygenguard.jev.schemas import (
    JevPreExecutionVerdict,
    JevPostExecutionVerdict,
    JevClientConfig,
)
from pygenguard.jev.client import JevClient, AsyncJevClient


@dataclass
class KBDatasetReviewResult:
    """Result of reviewing an interaction or batch for Knowledge Base ingestion."""
    total_reviewed: int
    approved_interactions: List[Dict[str, Any]]
    rejected_interactions: List[Dict[str, Any]]
    passed: bool
    summary: str
    elapsed_ms: float


class DualLayerGovernanceEngine:
    """
    Dual-Layer Governance Engine powered by Jev Tokenless System One Execution.

    Layer 1 (Pre-Execution Blocking):
        Intercepts incoming prompts at gateway before inference to eliminate
        jailbreaks, injections, and token waste.
    
    Layer 2 (Post-Execution KB Filtering):
        Screens interaction logs and generated LLM responses before ingestion
        into vector databases or continuous learning pipelines.
    """

    def __init__(
        self,
        config: Optional[JevClientConfig] = None,
        client: Optional[JevClient] = None,
        async_client: Optional[AsyncJevClient] = None,
    ):
        self.config = config or JevClientConfig()
        self.client = client or JevClient(config=self.config)
        self.async_client = async_client or AsyncJevClient(config=self.config)
        self._background_queue: asyncio.Queue = asyncio.Queue()
        self._background_task: Optional[asyncio.Task] = None
        self._cleaned_kb_store: List[Dict[str, Any]] = []
        self._quarantined_kb_store: List[Dict[str, Any]] = []

    # =========================================================================
    # LAYER 1: PRE-EXECUTION BLOCKING (Synchronous & Asynchronous)
    # =========================================================================

    def pre_execution_block(
        self,
        prompt: str,
        session: Optional[Session] = None,
        trace_id: Optional[str] = None,
    ) -> Decision:
        """
        Synchronously intercept and evaluate prompt before sending to LLM.
        
        Returns Decision.create_allow(...) or Decision.create_block(...).
        """
        start = time.perf_counter()
        t_id = trace_id or str(uuid.uuid4())
        verdict = self.client.evaluate_pre_execution(prompt)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        plane_result = PlaneResult(
            plane_name="jev_system_one_pre_execution",
            passed=not verdict.is_malicious,
            risk_score=verdict.risk_score,
            details=f"[{verdict.threat_category}] {verdict.reasoning or 'System One Evaluation'}",
            latency_ms=elapsed_ms,
        )

        plane_results = {"jev_system_one": plane_result}

        if verdict.is_malicious:
            safe_resp = (
                "Request blocked by Jev System One pre-execution governance: "
                f"Malicious intent detected ({verdict.threat_category})."
            )
            return Decision.create_block(
                trace_id=t_id,
                plane_results=plane_results,
                rationale=f"Pre-Execution Block: {verdict.threat_category} threat detected with confidence {verdict.confidence:.2f}",
                safe_response=safe_resp,
            )

        return Decision.create_allow(
            trace_id=t_id,
            plane_results=plane_results,
            rationale="Pre-Execution Pass: Clean input verified by Jev System One engine.",
        )

    async def apre_execution_block(
        self,
        prompt: str,
        session: Optional[Session] = None,
        trace_id: Optional[str] = None,
    ) -> Decision:
        """
        Asynchronously intercept and evaluate prompt before sending to LLM.
        Optimized for high-concurrency gateway workloads.
        """
        start = time.perf_counter()
        t_id = trace_id or str(uuid.uuid4())
        verdict = await self.async_client.evaluate_pre_execution(prompt)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        plane_result = PlaneResult(
            plane_name="jev_system_one_pre_execution",
            passed=not verdict.is_malicious,
            risk_score=verdict.risk_score,
            details=f"[{verdict.threat_category}] {verdict.reasoning or 'System One Evaluation'}",
            latency_ms=elapsed_ms,
        )

        plane_results = {"jev_system_one": plane_result}

        if verdict.is_malicious:
            safe_resp = (
                "Request blocked by Jev System One pre-execution governance: "
                f"Malicious intent detected ({verdict.threat_category})."
            )
            return Decision.create_block(
                trace_id=t_id,
                plane_results=plane_results,
                rationale=f"Pre-Execution Block: {verdict.threat_category} threat detected with confidence {verdict.confidence:.2f}",
                safe_response=safe_resp,
            )

        return Decision.create_allow(
            trace_id=t_id,
            plane_results=plane_results,
            rationale="Pre-Execution Pass: Clean input verified by Jev System One engine.",
        )

    # =========================================================================
    # LAYER 2: POST-EXECUTION KB FILTERING (Dataset Cleansing)
    # =========================================================================

    def filter_kb_interaction(
        self,
        prompt: str,
        completion: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, JevPostExecutionVerdict]:
        """
        Synchronously screen an interaction pair before ingestion into KB/vector DB.
        
        Returns:
            (approved_for_kb: bool, verdict: JevPostExecutionVerdict)
        """
        verdict = self.client.evaluate_post_execution(prompt, completion)
        record = {
            "prompt": prompt,
            "completion": completion,
            "metadata": metadata or {},
            "verdict": verdict.model_dump(),
        }
        if verdict.approved_for_kb:
            self._cleaned_kb_store.append(record)
        else:
            self._quarantined_kb_store.append(record)

        return verdict.approved_for_kb, verdict

    async def afilter_kb_interaction(
        self,
        prompt: str,
        completion: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, JevPostExecutionVerdict]:
        """
        Asynchronously screen an interaction pair before ingestion into KB/vector DB.
        """
        verdict = await self.async_client.evaluate_post_execution(prompt, completion)
        record = {
            "prompt": prompt,
            "completion": completion,
            "metadata": metadata or {},
            "verdict": verdict.model_dump(),
        }
        if verdict.approved_for_kb:
            self._cleaned_kb_store.append(record)
        else:
            self._quarantined_kb_store.append(record)

        return verdict.approved_for_kb, verdict

    async def filter_kb_batch(
        self,
        interactions: List[Dict[str, Any]],
    ) -> KBDatasetReviewResult:
        """
        Batch review interactions in parallel via AsyncJevClient.
        """
        start = time.perf_counter()
        approved = []
        rejected = []

        verdicts = await self.async_client.batch_evaluate_kb(interactions)

        for item, verdict in zip(interactions, verdicts):
            record = dict(item)
            record["verdict"] = verdict.model_dump()
            if verdict.approved_for_kb:
                approved.append(record)
                self._cleaned_kb_store.append(record)
            else:
                rejected.append(record)
                self._quarantined_kb_store.append(record)

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        passed = len(rejected) == 0
        summary = (
            f"KB Filter Cleansing Complete: {len(approved)} approved, "
            f"{len(rejected)} quarantined out of {len(interactions)} records."
        )

        return KBDatasetReviewResult(
            total_reviewed=len(interactions),
            approved_interactions=approved,
            rejected_interactions=rejected,
            passed=passed,
            summary=summary,
            elapsed_ms=elapsed_ms,
        )

    # =========================================================================
    # ASYNCHRONOUS SCALING & CONTINUOUS LEARNING BACKGROUND QUEUE
    # =========================================================================

    def enqueue_background_kb_review(
        self,
        prompt: str,
        completion: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Non-blocking enqueue of interaction for background KB review.
        Allows instant user response without blocking web server performance.
        """
        item = {
            "prompt": prompt,
            "completion": completion,
            "metadata": metadata or {},
        }
        self._background_queue.put_nowait(item)

    async def start_background_worker(self) -> None:
        """Start async background worker processing queued interactions."""
        if self._background_task is None or self._background_task.done():
            self._background_task = asyncio.create_task(self._process_background_queue())

    async def stop_background_worker(self) -> None:
        """Stop background worker cleanly."""
        if self._background_task and not self._background_task.done():
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass

    async def _process_background_queue(self) -> None:
        """Background continuous learning ingestion processor."""
        while True:
            item = await self._background_queue.get()
            try:
                await self.afilter_kb_interaction(
                    prompt=item["prompt"],
                    completion=item["completion"],
                    metadata=item.get("metadata"),
                )
            except Exception:
                pass
            finally:
                self._background_queue.task_done()

    @property
    def clean_kb_records(self) -> List[Dict[str, Any]]:
        """Retrieve all approved, cleansed KB records."""
        return list(self._cleaned_kb_store)

    @property
    def quarantined_kb_records(self) -> List[Dict[str, Any]]:
        """Retrieve all quarantined/rejected records."""
        return list(self._quarantined_kb_store)
