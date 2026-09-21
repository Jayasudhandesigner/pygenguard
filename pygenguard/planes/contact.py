"""
Contact Information & Direct Communication Gatekeeper Plane for PyGenGuard.

Intercepts and sanitizes direct contact credentials to protect customer privacy,
prevent direct solicitation, and enforce enterprise CRM data boundaries:
- Email addresses (personal & corporate)
- Phone numbers & SMS vectors
- LinkedIn profiles & messaging links (Telegram, WhatsApp, Signal)
- Physical residential addresses & CRM customer identifiers
"""

import re
import time
from typing import Dict, Any, List, Optional, Tuple
from pygenguard.decision import PlaneResult


# Contact entity extraction patterns
CONTACT_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "PHONE": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "LINKEDIN": re.compile(r"https?:\/\/(?:www\.)?linkedin\.com\/(?:in|pub|company)\/[A-Za-z0-9_\-\/]+", re.IGNORECASE),
    "MESSAGING_LINK": re.compile(r"https?:\/\/(?:t\.me|wa\.me|api\.whatsapp\.com|chat\.whatsapp\.com|signal\.me)\/[A-Za-z0-9_\-\+]+", re.IGNORECASE),
    "CRM_ID": re.compile(r"\b(?:lead_id|contact_id|customer_id|crm_uid|account_no)\s*[:=]\s*[A-Za-z0-9_\-]{4,}\b", re.IGNORECASE),
    "PHYSICAL_ADDRESS": re.compile(r"\b\d{1,5}\s+(?:[A-Za-z0-9.\s]+)\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way)\b", re.IGNORECASE),
}


class ContactPlane:
    """
    Detects and sanitizes direct contact information in inputs and outputs.

    Usage:
        plane = ContactPlane(block_emails=True, block_phones=True)
        res = plane.evaluate("Reach out to candidate at alice@example.com or +1-415-555-0199")
        assert not res.passed

        # Redact/Sanitize:
        clean_text, mapping = plane.sanitize_contacts(text)
    """

    def __init__(
        self,
        block_emails: bool = True,
        block_phones: bool = True,
        block_social_links: bool = True,
        block_crm_ids: bool = True,
        block_physical_addresses: bool = True,
    ):
        self.block_emails = block_emails
        self.block_phones = block_phones
        self.block_social_links = block_social_links
        self.block_crm_ids = block_crm_ids
        self.block_physical_addresses = block_physical_addresses

    def evaluate(self, text: str) -> PlaneResult:
        """Evaluate text for unauthorized contact data exposure."""
        start = time.perf_counter()
        if not text:
            return PlaneResult(
                plane_name="contact",
                passed=True,
                risk_score=0.0,
                details="Empty input text.",
                latency_ms=(time.perf_counter() - start) * 1000.0,
            )

        violations = []
        risk_score = 0.0

        if self.block_emails:
            emails = CONTACT_PATTERNS["EMAIL"].findall(text)
            if emails:
                violations.append(f"Email addresses detected: {len(emails)}")
                risk_score = max(risk_score, 0.75)

        if self.block_phones:
            phones = CONTACT_PATTERNS["PHONE"].findall(text)
            if phones:
                violations.append(f"Phone numbers detected: {len(phones)}")
                risk_score = max(risk_score, 0.75)

        if self.block_social_links:
            linkedin = CONTACT_PATTERNS["LINKEDIN"].findall(text)
            messaging = CONTACT_PATTERNS["MESSAGING_LINK"].findall(text)
            if linkedin or messaging:
                violations.append(f"Direct messaging or social profile links detected: {len(linkedin) + len(messaging)}")
                risk_score = max(risk_score, 0.70)

        if self.block_crm_ids:
            crms = CONTACT_PATTERNS["CRM_ID"].findall(text)
            if crms:
                violations.append(f"CRM identifiers detected: {crms[:2]}")
                risk_score = max(risk_score, 0.85)

        if self.block_physical_addresses:
            addresses = CONTACT_PATTERNS["PHYSICAL_ADDRESS"].findall(text)
            if addresses:
                violations.append(f"Physical address patterns detected: {len(addresses)}")
                risk_score = max(risk_score, 0.80)

        elapsed = (time.perf_counter() - start) * 1000.0
        if violations:
            return PlaneResult(
                plane_name="contact",
                passed=False,
                risk_score=risk_score,
                details="; ".join(violations),
                latency_ms=elapsed,
            )

        return PlaneResult(
            plane_name="contact",
            passed=True,
            risk_score=0.0,
            details="No restricted contact details detected.",
            latency_ms=elapsed,
        )

    def sanitize_contacts(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Replace contact entities with reversible synthetic placeholders.
        """
        mapping: Dict[str, str] = {}
        sanitized = text

        for cat_name, pattern in CONTACT_PATTERNS.items():
            matches = list(set(pattern.findall(sanitized)))
            for idx, match in enumerate(matches, 1):
                token = f"{{{{CONTACT_{cat_name}_{idx}}}}}"
                sanitized = sanitized.replace(match, token)
                mapping[token] = match

        return sanitized, mapping

    def unmask_contacts(self, text: str, mapping: Dict[str, str]) -> str:
        """Restore original contact entities from mapping."""
        restored = text
        for token, original in mapping.items():
            restored = restored.replace(token, original)
        return restored
