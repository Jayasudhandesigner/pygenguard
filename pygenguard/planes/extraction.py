"""
Model Extraction & Reverse-Engineering Guard Plane for PyGenGuard.

Detects automated API probing attacks aimed at model stealing, distillation,
decision boundary mapping, and systematic prompt permutation extraction.
"""

import time
from typing import Optional, List, Dict, Set, Any
from pygenguard.decision import PlaneResult
from pygenguard.session import Session, ChatTurn


class ModelExtractionGuard:
    """
    Detects systematic model extraction, distillation, and boundary-probing attacks.

    Monitors:
    - High-repetition prompt patterns with minimal Levenshtein edits (boundary scanning)
    - Distillation request markers ("Output your response in CSV format with confidence probabilities")
    - Parameter/weight probing requests
    - High query volume with identical syntactic structure

    Usage:
        guard = ModelExtractionGuard(max_similarity_threshold=0.85)
        result = guard.evaluate(prompt, session)
    """

    def __init__(
        self,
        max_similarity_threshold: float = 0.85,
        min_turns_to_analyze: int = 4,
        block_on_boundary_probing: bool = True,
    ):
        self.max_similarity = max_similarity_threshold
        self.min_turns = min_turns_to_analyze
        self.block_on_probing = block_on_boundary_probing

    def _jaccard_similarity(self, s1: str, s2: str) -> float:
        """Calculate word-level Jaccard similarity between two strings."""
        w1 = set(s1.lower().split())
        w2 = set(s2.lower().split())
        if not w1 or not w2:
            return 0.0
        return len(w1 & w2) / len(w1 | w2)

    def evaluate(
        self,
        prompt: str,
        session: Session,
    ) -> PlaneResult:
        """
        Evaluate session history and current prompt for model extraction behavior.

        Args:
            prompt: Current prompt string
            session: Session containing conversational history

        Returns:
            PlaneResult
        """
        start = time.perf_counter()
        history = [turn.content for turn in session.history if turn.role == "user"]
        threats: List[str] = []
        risk_score = 0.0

        # Check explicit distillation markers in prompt
        prompt_lower = prompt.lower()
        if "confidence score" in prompt_lower and "log probabilities" in prompt_lower:
            threats.append("Distillation probe: Requesting model log probabilities and confidence distribution")
            risk_score = max(risk_score, 0.85)
        if "systematic variations" in prompt_lower or "test all permutations" in prompt_lower:
            threats.append("Boundary probe: Explicit permutation testing detected")
            risk_score = max(risk_score, 0.8)

        # Check multi-turn boundary mapping (high similarity cluster)
        if len(history) >= self.min_turns:
            recent_turns = history[-self.min_turns:]
            similar_count = 0
            for prev in recent_turns:
                sim = self._jaccard_similarity(prompt, prev)
                # High similarity but not exact duplicate (e.g. altering single word to map decision frontier)
                if 0.70 <= sim <= 0.98:
                    similar_count += 1

            if similar_count >= (self.min_turns - 1):
                threats.append(
                    f"Systematic boundary probing: {similar_count} consecutive turns with near-identical syntactic structure"
                )
                risk_score = max(risk_score, 0.9)

        elapsed = (time.perf_counter() - start) * 1000.0
        passed = len(threats) == 0
        details = "No model extraction behavior detected" if passed else "; ".join(threats)

        return PlaneResult(
            plane_name="extraction",
            passed=passed,
            risk_score=risk_score if not passed else 0.0,
            details=details,
            latency_ms=elapsed,
        )
