"""
Reversible PII Pseudonymization Engine for PyGenGuard.

Replaces sensitive PII (emails, phone numbers, credit cards, SSNs, IP addresses)
with synthetic tokens (e.g. {{EMAIL_1}}, {{PHONE_1}}) before sending prompts to LLM
providers, and restores original values in generated model responses.
"""

import re
import asyncio
from typing import Tuple, Dict, Optional, List, Set, Any


# Standard regexes for common PII categories
PII_PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
    "PHONE": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}


class PIIMaskingEngine:
    """
    Reversible PII pseudonymization engine.

    Usage:
        engine = PIIMaskingEngine()
        masked_prompt, mapping = engine.mask_pii("Contact me at john@doe.com or 555-123-4567")
        # masked_prompt: "Contact me at {{EMAIL_1}} or {{PHONE_1}}"
        # mapping: {"{{EMAIL_1}}": "john@doe.com", "{{PHONE_1}}": "555-123-4567"}

        # Later, restore LLM response:
        original = engine.unmask_pii(llm_output, mapping)
    """

    def __init__(self, enabled_categories: Optional[List[str]] = None):
        self.categories = enabled_categories or list(PII_PATTERNS.keys())
        self._compiled = {
            cat: re.compile(PII_PATTERNS[cat]) for cat in self.categories if cat in PII_PATTERNS
        }

    def mask_pii(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Mask PII entities in text with reversible surrogate tokens.

        Returns:
            (masked_text, token_to_original_mapping)
        """
        mapping: Dict[str, str] = {}
        masked_text = text

        for cat, pattern in self._compiled.items():
            matches = list(set(pattern.findall(masked_text)))
            for idx, match in enumerate(matches, 1):
                token = f"{{{{{cat}_{idx}}}}}"
                masked_text = masked_text.replace(match, token)
                mapping[token] = match

        return masked_text, mapping

    def unmask_pii(self, text: str, mapping: Dict[str, str]) -> str:
        """Restore original PII values from token mapping."""
        unmasked = text
        for token, original in mapping.items():
            unmasked = unmasked.replace(token, original)
        return unmasked

    async def amask_pii(self, text: str) -> Tuple[str, Dict[str, str]]:
        """Asynchronously mask PII entities."""
        return self.mask_pii(text)

    async def aunmask_pii(self, text: str, mapping: Dict[str, str]) -> str:
        """Asynchronously unmask PII entities."""
        return self.unmask_pii(text, mapping)
