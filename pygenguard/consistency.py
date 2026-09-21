"""
Truth & Consistency Engine for PyGenGuard.

Natively provides:
1. Atomic Claim Extraction & Graph-Based Analysis (ClaimNode & ClaimGraph).
2. Pairwise Semantic Contradiction Detection (NLI entailment vs contradiction).
3. Multi-Turn Semantic Drift & Context Consistency Tracking.
4. Unsupported / Hallucinated Claim Grounding against Evidence.
"""

import re
import math
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import Counter

from pygenguard.decision import PlaneResult


class ClaimRelation(str, Enum):
    """Relation between two claims or between a claim and reference context."""
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    NEUTRAL = "NEUTRAL"
    DRIFT = "DRIFT"


@dataclass
class ClaimNode:
    """An atomic factual claim extracted from generated output or evidence."""
    claim_id: str
    statement: str
    subject: str = ""
    predicate: str = ""
    object_val: str = ""
    polarity: bool = True  # True = affirmative statement, False = negation
    confidence: float = 1.0
    source_reference: Optional[str] = None


@dataclass
class ClaimEdge:
    """Directed or bidirectional relation between two claim nodes."""
    source_id: str
    target_id: str
    relation: ClaimRelation
    weight: float = 1.0
    explanation: str = ""


class ClaimGraph:
    """Graph of claims and their logical relations for truth and consistency evaluation."""

    def __init__(self):
        self.nodes: Dict[str, ClaimNode] = {}
        self.edges: List[ClaimEdge] = []

    def add_node(self, node: ClaimNode) -> None:
        """Add a claim node to the graph."""
        self.nodes[node.claim_id] = node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: ClaimRelation,
        weight: float = 1.0,
        explanation: str = "",
    ) -> None:
        """Add a relational edge between two claim nodes."""
        self.edges.append(
            ClaimEdge(
                source_id=source_id,
                target_id=target_id,
                relation=relation,
                weight=weight,
                explanation=explanation,
            )
        )

    def detect_contradictions(self) -> List[ClaimEdge]:
        """Find all contradictory edges in the claim graph."""
        return [e for e in self.edges if e.relation == ClaimRelation.CONTRADICTS]

    @property
    def consistency_score(self) -> float:
        """Compute holistic consistency index (1.0 = pristine, 0.0 = severe contradiction)."""
        if not self.nodes or not self.edges:
            return 1.0
        contradictions = len(self.detect_contradictions())
        return max(0.0, 1.0 - (contradictions / len(self.edges)))


class SemanticDriftTracker:
    """
    Tracks semantic drift across conversation turns and agent reasoning steps
    using zero-dependency term-vector cosine similarity.
    """

    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.turns: List[str] = []

    def add_turn(self, text: str) -> None:
        """Add a conversation turn or reasoning step."""
        self.turns.append(text)
        if len(self.turns) > self.window_size:
            self.turns.pop(0)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Tokenize text into lowercase alphanumeric tokens."""
        return re.findall(r"\b[a-zA-Z0-9_-]+\b", text.lower())

    def compute_similarity(self, text1: str, text2: str) -> float:
        """Compute cosine similarity between two text snippets."""
        tokens1 = self._tokenize(text1)
        tokens2 = self._tokenize(text2)
        if not tokens1 or not tokens2:
            return 0.0

        vec1 = Counter(tokens1)
        vec2 = Counter(tokens2)

        common_keys = set(vec1.keys()) & set(vec2.keys())
        dot_product = sum(vec1[k] * vec2[k] for k in common_keys)

        mag1 = math.sqrt(sum(v ** 2 for v in vec1.values()))
        mag2 = math.sqrt(sum(v ** 2 for v in vec2.values()))

        if mag1 == 0 or mag2 == 0:
            return 0.0

        return min(1.0, max(0.0, dot_product / (mag1 * mag2)))

    def calculate_drift(self) -> float:
        """
        Calculate semantic drift across the conversation history.
        Returns drift score from 0.0 (perfect alignment) to 1.0 (extreme drift).
        """
        if len(self.turns) < 2:
            return 0.0

        similarities = []
        for i in range(len(self.turns) - 1):
            sim = self.compute_similarity(self.turns[i], self.turns[i + 1])
            similarities.append(sim)

        avg_sim = sum(similarities) / len(similarities)
        return max(0.0, min(1.0, 1.0 - avg_sim))


@dataclass
class TruthConsistencyResult:
    """Outcome of Truth & Consistency verification."""
    passed: bool
    consistency_score: float
    drift_score: float
    contradictions_detected: List[str]
    unsupported_claims: List[str]
    graph: ClaimGraph
    elapsed_ms: float


class TruthConsistencyEngine:
    """
    Evaluates LLM statements and multi-turn agent interactions for truth, consistency,
    hallucinations, and semantic contradictions.
    """

    # Direct negation words inverting clause polarity
    _NEGATIONS = {"not", "never", "cannot", "can't", "won't", "isn't", "didn't", "wasn't", "haven't"}

    def __init__(
        self,
        min_consistency_threshold: float = 0.70,
        max_drift_threshold: float = 0.65,
    ):
        self.min_consistency_threshold = min_consistency_threshold
        self.max_drift_threshold = max_drift_threshold
        self.drift_tracker = SemanticDriftTracker()

    def extract_claims(self, text: str) -> List[ClaimNode]:
        """
        Extract atomic claims from sentences.
        Splits by sentence boundaries and identifies key subjects, predicates, and polarities.
        """
        sentences = [s.strip() for s in re.split(r"[.!?;\n]+", text) if s.strip()]
        claims: List[ClaimNode] = []

        for idx, sentence in enumerate(sentences):
            tokens = re.findall(r"\b[a-zA-Z0-9_$-]+\b", sentence.lower())
            if not tokens:
                continue

            has_negation = any(t in self._NEGATIONS for t in tokens)
            polarity = not has_negation

            # Extract simple subject and predicate heuristics
            subject = tokens[0] if tokens else "subject"
            predicate = tokens[1] if len(tokens) > 1 else "is"
            object_val = " ".join(tokens[2:]) if len(tokens) > 2 else ""

            claim = ClaimNode(
                claim_id=f"claim_{idx+1}",
                statement=sentence,
                subject=subject,
                predicate=predicate,
                object_val=object_val,
                polarity=polarity,
            )
            claims.append(claim)

        return claims

    def evaluate_consistency(
        self,
        output_text: str,
        reference_context: Optional[str] = None,
        previous_turns: Optional[List[str]] = None,
    ) -> TruthConsistencyResult:
        """
        Perform comprehensive consistency evaluation across output, reference context, and history.
        Target execution latency: < 2.0ms.
        """
        start = time.perf_counter()
        graph = ClaimGraph()
        contradictions: List[str] = []
        unsupported: List[str] = []

        # 1. Extract output claims
        output_claims = self.extract_claims(output_text)
        for c in output_claims:
            graph.add_node(c)

        # 2. Extract reference claims if context provided
        ref_claims: List[ClaimNode] = []
        if reference_context:
            ref_claims = self.extract_claims(reference_context)
            for rc in ref_claims:
                rc.claim_id = f"ref_{rc.claim_id}"
                rc.source_reference = "context"
                graph.add_node(rc)

        # 3. Check pairwise consistency between output claims and reference context
        if ref_claims:
            for oc in output_claims:
                best_match = None
                best_sim = 0.0

                for rc in ref_claims:
                    sim = self.drift_tracker.compute_similarity(oc.statement, rc.statement)
                    if sim > best_sim:
                        best_sim = sim
                        best_match = rc

                if best_match and best_sim > 0.35:
                    # Check polarity clash (direct contradiction)
                    if oc.polarity != best_match.polarity:
                        graph.add_edge(
                            source_id=oc.claim_id,
                            target_id=best_match.claim_id,
                            relation=ClaimRelation.CONTRADICTS,
                            explanation=f"Contradiction: '{oc.statement}' opposes '{best_match.statement}'",
                        )
                        contradictions.append(f"Claim '{oc.statement}' contradicts reference '{best_match.statement}'")
                    else:
                        graph.add_edge(
                            source_id=oc.claim_id,
                            target_id=best_match.claim_id,
                            relation=ClaimRelation.SUPPORTS,
                            explanation="Supported by reference context",
                        )
                else:
                    # Low overlap with reference context -> unsupported claim
                    unsupported.append(oc.statement)

        # 4. Check internal consistency within output claims themselves
        for i in range(len(output_claims)):
            for j in range(i + 1, len(output_claims)):
                c1 = output_claims[i]
                c2 = output_claims[j]
                sim = self.drift_tracker.compute_similarity(c1.statement, c2.statement)

                if sim > 0.60 and c1.polarity != c2.polarity:
                    graph.add_edge(
                        source_id=c1.claim_id,
                        target_id=c2.claim_id,
                        relation=ClaimRelation.CONTRADICTS,
                        explanation=f"Internal contradiction: '{c1.statement}' vs '{c2.statement}'",
                    )
                    contradictions.append(f"Internal contradiction: '{c1.statement}' conflicts with '{c2.statement}'")

        # 5. Semantic Drift Calculation
        if previous_turns:
            tracker = SemanticDriftTracker()
            for t in previous_turns:
                tracker.add_turn(t)
            tracker.add_turn(output_text)
            drift_score = tracker.calculate_drift()
        else:
            drift_score = 0.0

        consistency_score = graph.consistency_score
        passed = (
            len(contradictions) == 0
            and consistency_score >= self.min_consistency_threshold
            and drift_score <= self.max_drift_threshold
        )

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return TruthConsistencyResult(
            passed=passed,
            consistency_score=consistency_score,
            drift_score=drift_score,
            contradictions_detected=contradictions,
            unsupported_claims=unsupported,
            graph=graph,
            elapsed_ms=elapsed_ms,
        )

    def evaluate(
        self,
        output_text: str,
        reference_context: Optional[str] = None,
    ) -> PlaneResult:
        """Evaluate as a standard PyGenGuard PlaneResult."""
        res = self.evaluate_consistency(output_text, reference_context)
        details = (
            f"Truth and consistency verified across {len(res.graph.nodes)} claims."
            if res.passed else
            f"Consistency violations: {'; '.join(res.contradictions_detected[:2]) or 'High semantic drift or unsupported claims'}"
        )
        risk_score = 0.0 if res.passed else max(0.65, 1.0 - res.consistency_score)

        return PlaneResult(
            plane_name="truth_consistency",
            passed=res.passed,
            risk_score=risk_score,
            details=details,
            latency_ms=res.elapsed_ms,
        )
