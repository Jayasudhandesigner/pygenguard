"""
Confidential Assets & Trade Secret Protection Plane for PyGenGuard.

Prevents unauthorized exposure of trade secrets, proprietary intellectual property,
internal compensation details, M&A communications, and NDA-classified data.
"""

import re
import time
from typing import Dict, Any, List, Optional
from pygenguard.decision import PlaneResult


# Confidentiality keywords and classifications
CONFIDENTIAL_PATTERNS = {
    "CONFIDENTIAL_MARK": re.compile(
        r"\b(?:strictly\s*confidential|proprietary\s*(?:and|&)\s*confidential|do\s*not\s*distribute|nda\s*protected|attorney-client\s*privilege|internal\s*eyes\s*only|company\s*confidential)\b",
        re.IGNORECASE,
    ),
    "MERGER_ACQUISITION": re.compile(
        r"\b(?:merger\s*agreement|acquisition\s*target|term\s*sheet|due\s*diligence\s*report|board\s*resolution\s*draft|confidential\s*m&a|shareholder\s*payout\s*schedule)\b",
        re.IGNORECASE,
    ),
    "COMPENSATION_PAYROLL": re.compile(
        r"\b(?:salary\s*band|equity\s*grant|employee\s*compensation|w-?2\s*income|base\s*salary\s*figure|executive\s*bonus\s*pool|payroll\s*schedule)\b",
        re.IGNORECASE,
    ),
    "TRADE_SECRET_ROADMAP": re.compile(
        r"\b(?:unreleased\s*(?:feature|product|v[0-9]+)|internal\s*roadmap|source\s*code\s*blueprint|proprietary\s*algorithm\s*formula|trade\s*secret\s*process|patent\s*pending\s*blueprint)\b",
        re.IGNORECASE,
    ),
    "INTERNAL_INFRASTRUCTURE": re.compile(
        r"\b(?:[A-Za-z0-9_\-]+\.internal\.corp|[A-Za-z0-9_\-]+\.internal\.aws|kubernetes\.default\.svc|10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:[0-9]{1,3}\.)[0-9]{1,3})\b",
        re.IGNORECASE,
    ),
}


class ConfidentialPlane:
    """
    Evaluates text for corporate confidential marks, compensation, M&A, and trade secrets.

    Usage:
        plane = ConfidentialPlane()
        res = plane.evaluate("Here is the Strictly Confidential unreleased product roadmap for Q4")
        assert not res.passed
    """

    def __init__(
        self,
        block_confidential_marks: bool = True,
        block_ma_transactions: bool = True,
        block_compensation: bool = True,
        block_trade_secrets: bool = True,
        block_internal_infra: bool = True,
        custom_confidential_terms: Optional[List[str]] = None,
    ):
        self.block_confidential_marks = block_confidential_marks
        self.block_ma_transactions = block_ma_transactions
        self.block_compensation = block_compensation
        self.block_trade_secrets = block_trade_secrets
        self.block_internal_infra = block_internal_infra
        self.custom_regex = re.compile("|".join(custom_confidential_terms), re.IGNORECASE) if custom_confidential_terms else None

    def evaluate(self, text: str) -> PlaneResult:
        """Evaluate text for unauthorized exposure of confidential items."""
        start = time.perf_counter()
        if not text:
            return PlaneResult(
                plane_name="confidential",
                passed=True,
                risk_score=0.0,
                details="Empty input text.",
                latency_ms=(time.perf_counter() - start) * 1000.0,
            )

        violations = []
        risk_score = 0.0

        if self.block_confidential_marks and CONFIDENTIAL_PATTERNS["CONFIDENTIAL_MARK"].search(text):
            violations.append("Confidential/NDA classification mark detected")
            risk_score = max(risk_score, 0.90)

        if self.block_ma_transactions and CONFIDENTIAL_PATTERNS["MERGER_ACQUISITION"].search(text):
            violations.append("Confidential M&A or transaction intelligence detected")
            risk_score = max(risk_score, 0.95)

        if self.block_compensation and CONFIDENTIAL_PATTERNS["COMPENSATION_PAYROLL"].search(text):
            violations.append("Employee payroll or executive compensation data detected")
            risk_score = max(risk_score, 0.85)

        if self.block_trade_secrets and CONFIDENTIAL_PATTERNS["TRADE_SECRET_ROADMAP"].search(text):
            violations.append("Proprietary trade secret or unreleased roadmap detected")
            risk_score = max(risk_score, 0.90)

        if self.block_internal_infra and CONFIDENTIAL_PATTERNS["INTERNAL_INFRASTRUCTURE"].search(text):
            violations.append("Internal private network endpoint or host detected")
            risk_score = max(risk_score, 0.85)

        if self.custom_regex and self.custom_regex.search(text):
            violations.append("Custom confidential business term detected")
            risk_score = max(risk_score, 0.90)

        elapsed = (time.perf_counter() - start) * 1000.0
        if violations:
            return PlaneResult(
                plane_name="confidential",
                passed=False,
                risk_score=risk_score,
                details="; ".join(violations),
                latency_ms=elapsed,
            )

        return PlaneResult(
            plane_name="confidential",
            passed=True,
            risk_score=0.0,
            details="No confidential items or trade secret leaks detected.",
            latency_ms=elapsed,
        )
