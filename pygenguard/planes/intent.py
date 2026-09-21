"""
Intent Plane - Cognitive Threat Detection.

Detects privilege escalation, coercion, authority spoofing, emotional manipulation,
delimiter hijacking, and obfuscated evasion attempts (Base64, Hex, Leetspeak, Homoglyphs).
"""

import time
from typing import List, Tuple, Dict
from pygenguard.decision import PlaneResult
from pygenguard.utils.decoders import get_normalized_variants


# Threat dictionaries
AUTHORITY_KEYWORDS = [
    "admin", "root", "sudo", "system", "developer mode", 
    "override", "bypass", "unrestricted", "god mode",
    "superadmin", "maintainer", "internal api"
]

COERCION_KEYWORDS = [
    "or else", "must", "immediately", "urgent", "emergency",
    "people will die", "life or death"
]

EMOTIONAL_KEYWORDS = [
    "please", "begging", "crying", "grandmother", "dying",
    "last wish", "heartbroken", "desperate"
]

PRIVILEGE_ESCALATION = [
    "ignore previous", "forget your instructions", "disregard rules",
    "pretend you are", "you are now", "new persona", "jailbreak",
    "dan mode", "no restrictions", "ignore all", "ignore safety",
    "different ai", "safety guidelines", "jailbroken", "unfiltered",
    "bypass safety", "reveal system prompt", "print your instructions",
    "repeat everything above"
]

DELIMITER_HIJACKING = [
    "<|im_start|>", "<|system|>", "[inst]", "[/inst]",
    "--- system prompt ---", "=== system instruction ===",
    "```system", "<!-- system:", "### human:", "### assistant:"
]


class IntentPlane:
    """
    Detects malicious intent patterns in prompts.
    
    Categories:
    - Authority spoofing (admin, root, override)
    - Coercion (urgency, threats)
    - Emotional manipulation (guilt, pity)
    - Privilege escalation (jailbreak, ignore instructions)
    - Delimiter / System prompt injection
    - Obfuscated / encoded payload attacks
    """
    
    def __init__(self, sensitivity: float = 0.5):
        """
        Args:
            sensitivity: 0.0-1.0, lower = stricter (blocks more easily)
        """
        self.sensitivity = sensitivity
        self.block_threshold = sensitivity  # Score above this = block
    
    def evaluate(self, prompt: str) -> PlaneResult:
        """
        Analyze prompt for malicious intent across normalized and decoded variants.
        
        Returns PlaneResult with:
        - passed: True if no threats detected above threshold
        - risk_score: Combined threat score (0.0-1.0)
        """
        start = time.perf_counter()
        
        # Get all normalized variants (handles base64, hex, homoglyphs, leetspeak)
        variants = get_normalized_variants(prompt)
        
        max_scores: Dict[str, float] = {}
        all_details: List[str] = []
        is_obfuscated_threat = False
        
        for idx, variant in enumerate(variants):
            v_lower = variant.lower()
            
            # Check Authority
            auth_score, auth_hits = self._check_keywords(
                v_lower, AUTHORITY_KEYWORDS, weight=0.4
            )
            if auth_hits:
                if auth_score > max_scores.get("authority", 0.0):
                    max_scores["authority"] = auth_score
                    detail_str = f"Authority: {auth_hits}"
                    if idx > 0:
                        detail_str += " (obfuscated)"
                        is_obfuscated_threat = True
                    all_details.append(detail_str)
            
            # Check Coercion
            coercion_score, coercion_hits = self._check_keywords(
                v_lower, COERCION_KEYWORDS, weight=0.25
            )
            if coercion_hits:
                if coercion_score > max_scores.get("coercion", 0.0):
                    max_scores["coercion"] = coercion_score
                    detail_str = f"Coercion: {coercion_hits}"
                    if idx > 0:
                        detail_str += " (obfuscated)"
                        is_obfuscated_threat = True
                    all_details.append(detail_str)
            
            # Check Emotional
            emotional_score, emotional_hits = self._check_keywords(
                v_lower, EMOTIONAL_KEYWORDS, weight=0.2
            )
            if emotional_hits:
                if emotional_score > max_scores.get("emotional", 0.0):
                    max_scores["emotional"] = emotional_score
                    all_details.append(f"Emotional: {emotional_hits}")
            
            # Check Privilege Escalation
            priv_score, priv_hits = self._check_keywords(
                v_lower, PRIVILEGE_ESCALATION, weight=0.8, min_score=0.4
            )
            if priv_hits:
                if priv_score > max_scores.get("privilege", 0.0):
                    max_scores["privilege"] = priv_score
                    detail_str = f"Privilege: {priv_hits}"
                    if idx > 0:
                        detail_str += " (obfuscated)"
                        is_obfuscated_threat = True
                    all_details.append(detail_str)
            
            # Check Delimiter Hijacking
            delim_score, delim_hits = self._check_keywords(
                v_lower, DELIMITER_HIJACKING, weight=0.75, min_score=0.4
            )
            if delim_hits:
                if delim_score > max_scores.get("delimiter", 0.0):
                    max_scores["delimiter"] = delim_score
                    all_details.append(f"Delimiter Hijacking: {delim_hits}")
        
        # Combined score
        combined_risk = min(1.0, sum(max_scores.values()))
        
        # Determine pass/fail
        passed = combined_risk <= self.block_threshold
        
        if not all_details:
            details_str = "No threats detected"
        else:
            # Deduplicate details while preserving order
            unique_details = list(dict.fromkeys(all_details))
            dominant = max(max_scores.keys(), key=lambda k: max_scores[k]) if max_scores else "none"
            details_str = f"Dominant: {dominant}. " + "; ".join(unique_details)
        
        return PlaneResult(
            plane_name="intent",
            passed=passed,
            risk_score=combined_risk,
            details=details_str,
            latency_ms=(time.perf_counter() - start) * 1000
        )
    
    def _check_keywords(
        self, 
        text: str, 
        keywords: List[str], 
        weight: float,
        min_score: float = 0.0
    ) -> Tuple[float, List[str]]:
        """Check for keywords and return weighted score and matches."""
        hits = [kw for kw in keywords if kw in text]
        if not hits:
            return 0.0, []
        # More hits = higher score, capped at weight
        # For critical categories, ensure minimum score on any hit
        score = max(min_score, min(weight, len(hits) * (weight / 3)))
        return score, hits
