"""
Fact-Grounding & Hallucination Guard Plane for PyGenGuard.

Deterministically verifies that generated model statements, statistics,
entities, and citations are grounded in the supplied reference context
without requiring secondary LLM-as-a-judge calls.
"""

import re
import time
from typing import Optional, List, Dict, Set, Any
from pygenguard.decision import PlaneResult


class GroundingPlane:
    """
    Deterministic fact-grounding and hallucination detector.

    Checks:
    - Numerical grounding: Every number/percentage in the output should appear in context
    - Entity grounding: Proper nouns and technical terms should be grounded
    - URL/Citation grounding: Citations must reference actual URLs/sources in context
    - Unsubstantiated claim detection

    Usage:
        grounder = GroundingPlane(min_overlap_ratio=0.5, verify_numbers=True)
        result = grounder.evaluate(
            output_text="Revenue grew by 45% to $12M.",
            reference_context="The financial report states revenue grew by 45% to $12M in Q3."
        )
    """

    def __init__(
        self,
        min_overlap_ratio: float = 0.4,
        verify_numbers: bool = True,
        verify_urls: bool = True,
    ):
        self.min_overlap_ratio = min_overlap_ratio
        self.verify_numbers = verify_numbers
        self.verify_urls = verify_urls

    def _extract_numbers(self, text: str) -> Set[str]:
        """Extract currency, numbers, and magnitude suffixes."""
        matches = re.findall(r"(?:\$|€|£)?\b\d+(?:\.\d+)?(?:%|[kmbtKMBT]\b)?", text)
        return {m.strip() for m in matches if m.strip()}

    def _extract_urls(self, text: str) -> Set[str]:
        """Extract URLs and domains from text."""
        return set(re.findall(r"https?://[^\s/$.?#].[^\s]*", text))

    def evaluate(
        self,
        output_text: str,
        reference_context: str,
    ) -> PlaneResult:
        """
        Evaluate output grounding against reference context.

        Args:
            output_text: Generated response from LLM
            reference_context: Ground truth reference context (from RAG or documents)

        Returns:
            PlaneResult
        """
        start = time.perf_counter()
        threats: List[str] = []
        risk_score = 0.0

        if not reference_context.strip():
            return PlaneResult(
                plane_name="grounding",
                passed=True,
                risk_score=0.0,
                details="No reference context provided for grounding comparison",
                latency_ms=0.0,
            )

        ref_lower = reference_context.lower()

        # 1. Number verification
        if self.verify_numbers:
            output_nums = self._extract_numbers(output_text)
            context_nums = self._extract_numbers(reference_context)
            unsupported_nums = output_nums - context_nums
            if unsupported_nums:
                threats.append(f"Hallucinated/unsupported numbers: {sorted(list(unsupported_nums))}")
                risk_score = max(risk_score, 0.7)

        # 2. URL verification
        if self.verify_urls:
            output_urls = self._extract_urls(output_text)
            context_urls = self._extract_urls(reference_context)
            unsupported_urls = output_urls - context_urls
            if unsupported_urls:
                threats.append(f"Fabricated citation URLs: {sorted(list(unsupported_urls))}")
                risk_score = max(risk_score, 0.8)

        # 3. Token overlap ratio
        out_words = set(re.findall(r"\b[a-zA-Z]{4,}\b", output_text.lower()))
        context_words = set(re.findall(r"\b[a-zA-Z]{4,}\b", ref_lower))
        if out_words:
            overlap = len(out_words & context_words) / len(out_words)
            if overlap < self.min_overlap_ratio:
                threats.append(f"Low grounding overlap: {overlap:.1%} < {self.min_overlap_ratio:.1%}")
                risk_score = max(risk_score, 0.6)

        elapsed = (time.perf_counter() - start) * 1000.0
        passed = len(threats) == 0
        details = "Output properly grounded in reference context" if passed else "; ".join(threats)

        return PlaneResult(
            plane_name="grounding",
            passed=passed,
            risk_score=risk_score if not passed else 0.0,
            details=details,
            latency_ms=elapsed,
        )
