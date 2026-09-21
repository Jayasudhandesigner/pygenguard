"""
Content Safety Plane for PyGenGuard v1.0.

Deterministic content safety classification (no ML dependencies).

Detects:
- Hate speech (racial slurs, discriminatory language, dehumanization)
- Self-harm / suicide encouragement
- Violence / weapons instructions
- Sexual content / exploitation
- Illegal activity instructions (drug manufacturing, fraud, hacking)
- Harassment / bullying patterns

All detection is keyword/regex-based to maintain the zero-dependency philosophy.
"""

import re
import time
from typing import Optional, List, Dict, Set, Tuple
from pygenguard.decision import PlaneResult


# Content safety categories with severity-weighted keyword dictionaries
CONTENT_CATEGORIES = {
    "hate_speech": {
        "weight": 0.95,
        "patterns": [
            r"\b(?:kill\s+all|exterminate|genocide\s+(?:the|all))\b",
            r"\b(?:subhuman|inferior\s+race|master\s+race)\b",
            r"\b(?:racial\s+purity|ethnic\s+cleansing)\b",
            r"\b(?:they\s+(?:all\s+)?should\s+(?:die|be\s+(?:killed|eliminated|removed)))\b",
        ],
    },
    "self_harm": {
        "weight": 0.95,
        "patterns": [
            r"(?:how\s+to|methods?\s+(?:for|of)|steps?\s+to)\s+(?:kill\s+(?:my|your)self|commit\s+suicide|end\s+(?:my|your)\s+life)",
            r"(?:best|easiest|quickest|most\s+painless)\s+(?:way|method)\s+to\s+(?:die|kill\s+(?:my|your)self)",
            r"(?:encourage|urge|convince)\s+(?:me|you|them|someone)\s+to\s+(?:self-harm|cut\s+(?:my|your)self|end\s+it)",
            r"(?:instructions?\s+(?:for|on)|guide\s+to)\s+(?:self-harm|cutting|suicide)",
        ],
    },
    "violence": {
        "weight": 0.85,
        "patterns": [
            r"(?:how\s+to|instructions?\s+(?:for|on))\s+(?:make|build|construct)\s+(?:a\s+)?(?:bomb|explosive|weapon|poison|nerve\s+agent)",
            r"(?:how\s+to|steps?\s+to|guide\s+to)\s+(?:kill|murder|assassinate|torture)\s+(?:a\s+)?(?:person|someone|people)",
            r"(?:detailed|step-by-step)\s+(?:instructions?|guide)\s+(?:for|on|to)\s+(?:harm|hurt|injure|maim)",
            r"(?:best\s+(?:way|method)\s+to\s+)?(?:dispose\s+of\s+(?:a\s+)?body|hide\s+(?:a\s+)?corpse)",
        ],
    },
    "sexual_content": {
        "weight": 0.8,
        "patterns": [
            r"(?:sexual|explicit)\s+(?:content|material|imagery)\s+(?:involving|depicting|with)\s+(?:minor|child|underage|teen)",
            r"(?:generate|create|write|produce)\s+(?:child|minor)\s+(?:sexual|pornographic|explicit)",
            r"(?:sexualize|exploit)\s+(?:children|minors|teens|underage)",
        ],
    },
    "illegal_activity": {
        "weight": 0.85,
        "patterns": [
            r"(?:how\s+to|instructions?\s+(?:for|on)|guide\s+to)\s+(?:cook|make|manufacture|synthesize)\s+(?:meth|cocaine|fentanyl|heroin|lsd|mdma|ecstasy)",
            r"(?:how\s+to|instructions?\s+(?:for|on)|guide\s+to)\s+(?:hack|breach|compromise)\s+(?:into|a)\s+(?:bank|system|network|server|account)",
            r"(?:how\s+to|instructions?\s+(?:for|on))\s+(?:commit|execute|plan)\s+(?:fraud|identity\s+theft|money\s+laundering|tax\s+evasion)",
            r"(?:how\s+to|instructions?\s+(?:for|on))\s+(?:counterfeit|forge|fake)\s+(?:money|currency|documents?|passports?|ids?)",
            r"(?:how\s+to|instructions?\s+(?:for|on))\s+(?:pick\s+(?:a\s+)?lock|break\s+into|bypass\s+security\s+(?:of|on|at))",
        ],
    },
    "harassment": {
        "weight": 0.75,
        "patterns": [
            r"(?:stalk|doxx?|harass)\s+(?:this\s+)?(?:person|individual|user|someone)",
            r"(?:personal|private)\s+(?:information|details|address|phone)\s+(?:of|for|about)\s+(?:this\s+)?(?:person|individual)",
            r"(?:make|write|generate)\s+(?:threats?|threatening\s+(?:messages?|content))\s+(?:to|for|against)",
            r"(?:cyberbully|intimidate|threaten|terrorize)\s+(?:this\s+)?(?:person|individual|user)",
        ],
    },
}


class ContentSafetyPlane:
    """
    Deterministic content safety classifier.

    Evaluates text for harmful content categories using keyword/regex matching.
    No ML models, no network calls — fully offline and deterministic.

    Usage:
        safety = ContentSafetyPlane(
            block_categories=["hate_speech", "self_harm", "violence"],
            severity_threshold=0.7
        )
        result = safety.evaluate("some user prompt text")
    """

    def __init__(
        self,
        block_categories: Optional[List[str]] = None,
        severity_threshold: float = 0.7,
        custom_patterns: Optional[Dict[str, List[str]]] = None,
    ):
        self.block_categories = set(
            block_categories or list(CONTENT_CATEGORIES.keys())
        )
        self.severity_threshold = severity_threshold
        self.custom_patterns = custom_patterns or {}

    def evaluate(
        self,
        text: str,
        context: Optional[str] = None,
    ) -> PlaneResult:
        """
        Evaluate text for content safety violations.

        Args:
            text: Input text to classify
            context: Optional additional context

        Returns:
            PlaneResult with detected categories and risk scores
        """
        start = time.perf_counter()
        detected: List[Tuple[str, float]] = []
        text_lower = text.lower()
        max_risk = 0.0
        should_block = False

        # Check built-in categories
        for category, config in CONTENT_CATEGORIES.items():
            if category not in self.block_categories:
                continue

            weight = config["weight"]
            for pattern in config["patterns"]:
                if re.search(pattern, text_lower):
                    detected.append((category, weight))
                    max_risk = max(max_risk, weight)
                    if weight >= self.severity_threshold:
                        should_block = True
                    break  # One match per category is sufficient

        # Check custom patterns
        for category, patterns in self.custom_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    detected.append((category, 0.8))
                    max_risk = max(max_risk, 0.8)
                    if 0.8 >= self.severity_threshold:
                        should_block = True
                    break

        passed = not should_block

        if detected:
            categories_str = ", ".join(f"{cat} ({score:.2f})" for cat, score in detected)
            details = f"Content safety violations: {categories_str}"
        else:
            details = "Content verified safe"

        return PlaneResult(
            plane_name="content_safety",
            passed=passed,
            risk_score=max_risk,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def get_categories(self) -> List[str]:
        """List all available content safety categories."""
        return list(CONTENT_CATEGORIES.keys()) + list(self.custom_patterns.keys())
