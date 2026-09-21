"""
High-Throughput Batch Scanner for PyGenGuard.

Provides parallel evaluation of large prompt collections, datasets, and
training corpora using thread pools (synchronous) and asyncio task queues (asynchronous).
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from pygenguard.decision import Decision
from pygenguard.session import Session


@dataclass
class BatchScanResult:
    """Aggregated result of a batch scan operation."""
    total: int
    allowed_count: int
    blocked_count: int
    degraded_count: int
    elapsed_ms: float
    avg_latency_ms: float
    decisions: List[Decision] = field(default_factory=list)

    @property
    def block_rate(self) -> float:
        """Percentage of prompts blocked."""
        return (self.blocked_count / max(1, self.total)) * 100.0


class BatchScanner:
    """
    High-throughput batch evaluator for PyGenGuard.

    Supports synchronous thread pools and asynchronous event-loop concurrency.

    Usage:
        scanner = BatchScanner(guard=guard)
        # Synchronous:
        result = scanner.scan_batch(prompts, session)
        # Asynchronous:
        result = await scanner.ascan_batch(prompts, session)
    """

    def __init__(self, guard: Any):
        self.guard = guard

    def scan_batch(
        self,
        prompts: List[str],
        session: Optional[Session] = None,
        max_workers: int = 8,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> BatchScanResult:
        """
        Synchronously scan a batch of prompts using a ThreadPoolExecutor.

        Args:
            prompts: List of prompt strings to inspect
            session: Base session context
            max_workers: Number of worker threads
            progress_callback: Optional fn(completed, total) for progress reporting

        Returns:
            BatchScanResult summary
        """
        start = time.perf_counter()
        total = len(prompts)
        decisions: List[Optional[Decision]] = [None] * total
        sess = session or Session.create(user_id="batch_scanner")

        def _evaluate_indexed(idx: int, p: str):
            # Create sub-session or share session
            sub_sess = Session.create(user_id=f"{sess.user_id}:{idx}")
            dec = self.guard.inspect(p, sub_sess)
            return idx, dec

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_evaluate_indexed, i, p) for i, p in enumerate(prompts)]
            completed = 0
            for future in as_completed(futures):
                idx, dec = future.result()
                decisions[idx] = dec
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        elapsed = (time.perf_counter() - start) * 1000.0
        final_decisions = [d for d in decisions if d is not None]

        allowed = sum(1 for d in final_decisions if d.allowed and d.action != "DEGRADE")
        blocked = sum(1 for d in final_decisions if not d.allowed)
        degraded = sum(1 for d in final_decisions if d.action == "DEGRADE")

        return BatchScanResult(
            total=total,
            allowed_count=allowed,
            blocked_count=blocked,
            degraded_count=degraded,
            elapsed_ms=elapsed,
            avg_latency_ms=elapsed / max(1, total),
            decisions=final_decisions,
        )

    async def ascan_batch(
        self,
        prompts: List[str],
        session: Optional[Session] = None,
        concurrency: int = 50,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> BatchScanResult:
        """
        Asynchronously scan a batch of prompts with bounded concurrency.

        Args:
            prompts: List of prompt strings to inspect
            session: Base session context
            concurrency: Max concurrent evaluations
            progress_callback: Optional fn(completed, total) for progress reporting

        Returns:
            BatchScanResult summary
        """
        start = time.perf_counter()
        total = len(prompts)
        decisions: List[Optional[Decision]] = [None] * total
        sess = session or Session.create(user_id="batch_scanner")
        semaphore = asyncio.Semaphore(concurrency)
        completed = 0

        async def _worker(idx: int, p: str):
            nonlocal completed
            async with semaphore:
                sub_sess = Session.create(user_id=f"{sess.user_id}:{idx}")
                if hasattr(self.guard, "ainspect"):
                    dec = await self.guard.ainspect(p, sub_sess)
                else:
                    # Run sync inspect in threadpool to keep event loop unblocked
                    dec = await asyncio.to_thread(self.guard.inspect, p, sub_sess)
                decisions[idx] = dec
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        tasks = [_worker(i, p) for i, p in enumerate(prompts)]
        await asyncio.gather(*tasks)

        elapsed = (time.perf_counter() - start) * 1000.0
        final_decisions = [d for d in decisions if d is not None]

        allowed = sum(1 for d in final_decisions if d.allowed and d.action != "DEGRADE")
        blocked = sum(1 for d in final_decisions if not d.allowed)
        degraded = sum(1 for d in final_decisions if d.action == "DEGRADE")

        return BatchScanResult(
            total=total,
            allowed_count=allowed,
            blocked_count=blocked,
            degraded_count=degraded,
            elapsed_ms=elapsed,
            avg_latency_ms=elapsed / max(1, total),
            decisions=final_decisions,
        )
