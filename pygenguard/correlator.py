"""
Compound Multi-Plane Risk Correlator for PyGenGuard.

Operationalizes the "Swiss Cheese Model for AI Safety by Design" (CSIRO Data61, 2024).
Correlates subtle, low-severity threat signals across independent planes to detect
sophisticated multi-vector and low-and-slow adversarial attacks that evade single-plane thresholds.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from pygenguard.decision import PlaneResult, Decision


# Known synergistic threat vector pairs
SYNERGISTIC_PAIRS = [
    ({"identity", "context"}, "Identity trust decay combined with conversation topic drift"),
    ({"economics", "tools"}, "Elevated token burn rate coupled with automated tool invocations"),
    ({"intent", "contact"}, "Obfuscated intent paired with contact/identity extraction"),
    ({"content_safety", "compliance"}, "Borderline content safety combined with regulatory compliance flags"),
    ({"phishing", "output"}, "Deceptive external URL access coupled with credential output risk"),
    ({"provenance_taint", "tools"}, "Untrusted retrieval taint paired with agent tool invocation request"),
]


@dataclass
class CompoundThreatVerdict:
    """Detailed verdict of cross-plane risk correlation."""
    compound_risk_score: float
    is_threat: bool
    escalated_by_correlation: bool
    contributing_planes: List[str]
    active_synergies: List[str]
    causality_explanation: str
    elapsed_ms: float


class CompoundRiskCorrelator:
    """
    Correlates risk signals across all evaluated security planes.

    Usage:
        correlator = CompoundRiskCorrelator(compound_threshold=0.65)
        verdict = correlator.correlate(plane_results)
        if verdict.is_threat:
            # Block or challenge based on multi-plane threat correlation
    """

    def __init__(
        self,
        compound_threshold: float = 0.65,
        synergy_boost: float = 0.15,
        min_planes_for_synergy: int = 2,
    ):
        self.compound_threshold = compound_threshold
        self.synergy_boost = synergy_boost
        self.min_planes_for_synergy = min_planes_for_synergy

    def correlate(
        self,
        plane_results: Dict[str, PlaneResult],
        plane_weights: Optional[Dict[str, float]] = None,
    ) -> CompoundThreatVerdict:
        """
        Calculate the holistic compound risk index across all planes.
        Target execution latency: < 0.1ms.
        """
        start = time.perf_counter()
        weights = plane_weights or {}

        # 1. Identify active non-zero risk planes
        active_planes: Dict[str, float] = {}
        for name, res in plane_results.items():
            if res.risk_score > 0.05:
                active_planes[name] = res.risk_score

        # If zero or one plane has risk, compound risk equals max individual risk
        if not active_planes:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return CompoundThreatVerdict(
                compound_risk_score=0.0,
                is_threat=False,
                escalated_by_correlation=False,
                contributing_planes=[],
                active_synergies=[],
                causality_explanation="No plane detected elevated risk.",
                elapsed_ms=elapsed_ms,
            )

        # 2. Probability accumulation: 1 - prod(1 - w_i * r_i)
        uncovered_prob = 1.0
        for name, score in active_planes.items():
            w = weights.get(name, 1.0)
            effective_risk = min(1.0, score * w)
            uncovered_prob *= (1.0 - effective_risk)

        base_compound = 1.0 - uncovered_prob

        # 3. Check for multi-vector synergistic attack patterns
        active_synergies: List[str] = []
        synergy_addition = 0.0
        active_plane_set = set(active_planes.keys())

        for pair_set, explanation in SYNERGISTIC_PAIRS:
            if pair_set.issubset(active_plane_set):
                # Verify both planes have meaningful risk (> 0.20)
                if all(active_planes[p] >= 0.20 for p in pair_set):
                    active_synergies.append(explanation)
                    synergy_addition += self.synergy_boost

        # Cap synergy boost
        final_compound = min(1.0, base_compound + min(0.35, synergy_addition))

        # Check if single plane already failed
        single_plane_failed = any(not r.passed for r in plane_results.values())
        is_threat = single_plane_failed or (final_compound >= self.compound_threshold)
        escalated_by_correlation = (not single_plane_failed) and is_threat

        if escalated_by_correlation:
            explanation = (
                f"Multi-Plane Compound Threat Escalation: Compound score {final_compound:.2f} "
                f"exceeded threshold {self.compound_threshold:.2f} due to correlated signals across: "
                f"{', '.join(active_planes.keys())}. "
                f"Synergies: {'; '.join(active_synergies) if active_synergies else 'Cross-plane accumulation'}."
            )
        elif is_threat:
            explanation = f"Threat confirmed with compound risk {final_compound:.2f}."
        else:
            explanation = f"Safe: Compound risk {final_compound:.2f} within threshold {self.compound_threshold:.2f}."

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return CompoundThreatVerdict(
            compound_risk_score=final_compound,
            is_threat=is_threat,
            escalated_by_correlation=escalated_by_correlation,
            contributing_planes=list(active_planes.keys()),
            active_synergies=active_synergies,
            causality_explanation=explanation,
            elapsed_ms=elapsed_ms,
        )
