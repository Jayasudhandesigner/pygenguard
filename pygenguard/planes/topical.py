"""
Topical Boundary Guard Plane for PyGenGuard.

Enforces domain boundary constraints, keeping conversational agents strictly
within approved business topics while blocking off-topic, prohibited, or
competitor inquiries (inspired by NeMo Guardrails, but sub-0.1ms tokenless).
"""

import time
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Any, Union

from pygenguard.decision import PlaneResult


@dataclass
class TopicDefinition:
    """Specification of an allowed or prohibited conversational topic."""
    name: str
    keywords: List[str] = field(default_factory=list)
    description: str = ""
    weight: float = 1.0


class TopicalBoundaryPlane:
    """
    Topical and Domain Boundary Defense Plane.
    
    Prevents generative AI from engaging in off-topic discussions, out-of-scope tasks,
    prohibited discussions (e.g., politics, competitors, crypto, medical advice),
    and redirects users cleanly back to permitted domain capabilities.
    """

    def __init__(
        self,
        allowed_topics: Optional[List[Union[str, TopicDefinition]]] = None,
        prohibited_topics: Optional[List[Union[str, TopicDefinition]]] = None,
        strict_mode: bool = False,
        redirection_message: str = "This query is outside the designated topic scope of this assistant.",
        case_sensitive: bool = False,
    ):
        self.strict_mode = strict_mode
        self.redirection_message = redirection_message
        self.case_sensitive = case_sensitive

        self.allowed_topics: List[TopicDefinition] = self._normalize_topics(allowed_topics or [])
        self.prohibited_topics: List[TopicDefinition] = self._normalize_topics(prohibited_topics or [])

    def _normalize_topics(self, topics: List[Any]) -> List[TopicDefinition]:
        res = []
        for t in topics:
            if isinstance(t, TopicDefinition):
                res.append(t)
            elif isinstance(t, str):
                words = [w.strip() for w in re.split(r"[,;|\s]+", t) if w.strip()]
                res.append(TopicDefinition(name=t, keywords=words or [t]))
            elif isinstance(t, dict):
                res.append(TopicDefinition(**t))
        return res

    def add_allowed_topic(self, name: str, keywords: Optional[List[str]] = None) -> None:
        """Add an approved topic to the boundary."""
        self.allowed_topics.append(TopicDefinition(name=name, keywords=keywords or [name]))

    def add_prohibited_topic(self, name: str, keywords: Optional[List[str]] = None) -> None:
        """Add a prohibited topic that triggers immediate blocking."""
        self.prohibited_topics.append(TopicDefinition(name=name, keywords=keywords or [name]))

    def evaluate(self, prompt: str) -> PlaneResult:
        """
        Evaluate if a user prompt conforms to topic boundaries.
        Target latency: < 0.1ms.
        """
        start_time = time.perf_counter()
        clean_text = prompt if self.case_sensitive else prompt.lower()
        tokens = set(re.findall(r"\b\w+\b", clean_text))

        # Check Step 1: Prohibited Topics (Immediate Violation)
        for topic in self.prohibited_topics:
            matched_keywords = []
            for kw in topic.keywords:
                pattern = kw if self.case_sensitive else kw.lower()
                if " " in pattern:
                    if pattern in clean_text:
                        matched_keywords.append(pattern)
                elif pattern in tokens:
                    matched_keywords.append(pattern)

            if matched_keywords:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return PlaneResult(
                    plane_name="topical_boundary",
                    passed=False,
                    risk_score=0.90,
                    details=f"Prohibited topic '{topic.name}' detected (matched: {matched_keywords}). {self.redirection_message}",
                    latency_ms=round(elapsed_ms, 3),
                )

        # Check Step 2: Allowed Topics (In strict mode, must match at least one allowed topic)
        if self.strict_mode and self.allowed_topics:
            matched_allowed = []
            for topic in self.allowed_topics:
                for kw in topic.keywords:
                    pattern = kw if self.case_sensitive else kw.lower()
                    if " " in pattern:
                        if pattern in clean_text:
                            matched_allowed.append(topic.name)
                            break
                    elif pattern in tokens:
                        matched_allowed.append(topic.name)
                        break

            if not matched_allowed:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return PlaneResult(
                    plane_name="topical_boundary",
                    passed=False,
                    risk_score=0.75,
                    details=f"Query is out of scope. {self.redirection_message}",
                    latency_ms=round(elapsed_ms, 3),
                )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return PlaneResult(
            plane_name="topical_boundary",
            passed=True,
            risk_score=0.05,
            details="Topic validation passed within permitted domain boundaries.",
            latency_ms=round(elapsed_ms, 3),
        )
