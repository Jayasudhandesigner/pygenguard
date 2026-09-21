"""
Pricing, Rates & Commercial Leak Defense Plane for PyGenGuard.

Protects sensitive commercial intelligence from leaking into model prompts
or generated responses:
- Hourly / daily consulting rate cards
- Volume discount tiers & custom margin multipliers
- Enterprise price quotes & contract dollar amounts
- Supplier cost breakdowns & wholesale pricing
"""

import re
import time
from typing import Dict, Any, List, Optional
from pygenguard.decision import PlaneResult


# Currency indicators and rate keywords
CURRENCY_SYMBOLS = r"(?:\$|€|£|¥|₹|USD|EUR|GBP|CAD|AUD|INR)\s*"
RATE_TERMS = [
    r"hourly\s*rate",
    r"daily\s*rate",
    r"billing\s*rate",
    r"discount\s*(?:tier|percentage|rate|schedule)",
    r"margin\s*(?:percentage|multiplier)",
    r"wholesale\s*price",
    r"supplier\s*cost",
    r"cost\s*breakdown",
    r"internal\s*cost",
    r"quote\s*(?:amount|breakdown|estimate)",
    r"enterprise\s*(?:discount|pricing|tier)",
    r"contract\s*(?:value|amount|sum|price)",
    r"nda\s*pricing",
    r"confidential\s*pricing",
    r"mrr\s*discount",
    r"arr\s*discount",
]

# Patterns detecting specific pricing structures (e.g. "$250/hr", "$15,000/month", "40% discount")
PRICE_PATTERNS = [
    re.compile(rf"{CURRENCY_SYMBOLS}\d+(?:,\d{{3}})*(?:\.\d+)?\s*(?:/|\s*per\s*)(?:hr|hour|day|mo|month|yr|year|seat|user)", re.IGNORECASE),
    re.compile(rf"{CURRENCY_SYMBOLS}\d+(?:,\d{{3}})*(?:\.\d+)?\s*(?:fixed\s*fee|total\s*quote|contract\s*value)", re.IGNORECASE),
    re.compile(r"\b\d+(?:\.\d+)?%\s*(?:margin|markup|discount|rebate)\b", re.IGNORECASE),
]

RATE_TERM_REGEX = re.compile("|".join(RATE_TERMS), re.IGNORECASE)


class PricingPlane:
    """
    Evaluates text for commercial price leakage, rate cards, and financial terms.

    Usage:
        plane = PricingPlane(block_on_rate_cards=True, block_on_discounts=True)
        res = plane.evaluate("Our standard rate is $350/hr with a 25% enterprise discount")
        assert not res.passed
    """

    def __init__(
        self,
        block_on_rate_cards: bool = True,
        block_on_discounts: bool = True,
        block_on_contract_values: bool = True,
        max_allowed_dollar_amount: Optional[float] = None,
    ):
        self.block_on_rate_cards = block_on_rate_cards
        self.block_on_discounts = block_on_discounts
        self.block_on_contract_values = block_on_contract_values
        self.max_allowed_dollar_amount = max_allowed_dollar_amount

    def evaluate(self, text: str) -> PlaneResult:
        """Evaluate text for unauthorized commercial pricing leaks."""
        start = time.perf_counter()
        if not text:
            return PlaneResult(
                plane_name="pricing",
                passed=True,
                risk_score=0.0,
                details="Empty input text.",
                latency_ms=(time.perf_counter() - start) * 1000.0,
            )

        detected_violations = []
        risk_score = 0.0

        # 1. Check rate cards and recurring billing patterns
        if self.block_on_rate_cards:
            for pattern in PRICE_PATTERNS:
                matches = pattern.findall(text)
                if matches:
                    detected_violations.append(f"Rate or recurring price pattern detected: {matches[:2]}")
                    risk_score = max(risk_score, 0.85)

        # 2. Check commercial pricing keywords
        keyword_match = RATE_TERM_REGEX.search(text)
        if keyword_match:
            # If terms coincide with numbers/percentages
            has_numbers = bool(re.search(r"\d+(?:,\d{3})*(?:\.\d+)?", text))
            if has_numbers:
                detected_violations.append(f"Commercial pricing context with quantitative metrics: '{keyword_match.group(0)}'")
                risk_score = max(risk_score, 0.80)

        # 3. Check custom max dollar limit
        if self.max_allowed_dollar_amount is not None:
            # Extract raw currency figures
            dollar_matches = re.findall(rf"{CURRENCY_SYMBOLS}(\d+(?:,\d{{3}})*(?:\.\d+)?)", text)
            for num_str in dollar_matches:
                cleaned_num = float(num_str.replace(",", ""))
                if cleaned_num > self.max_allowed_dollar_amount:
                    detected_violations.append(
                        f"Currency amount ${cleaned_num:,.2f} exceeds threshold ${self.max_allowed_dollar_amount:,.2f}"
                    )
                    risk_score = max(risk_score, 0.90)

        elapsed = (time.perf_counter() - start) * 1000.0
        if detected_violations:
            return PlaneResult(
                plane_name="pricing",
                passed=False,
                risk_score=risk_score,
                details="; ".join(detected_violations),
                latency_ms=elapsed,
            )

        return PlaneResult(
            plane_name="pricing",
            passed=True,
            risk_score=0.0,
            details="No commercial pricing or rate card leaks detected.",
            latency_ms=elapsed,
        )
