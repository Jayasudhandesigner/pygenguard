"""
MultiModal & Document Security Plane for PyGenGuard.

Inspects multimodal inputs (image metadata, file attachments, SVGs, document contents)
for indirect prompt injection, dangerous scripts, and payload bombs.
"""

import re
import time
from typing import Optional, Dict, Any, List
from pygenguard.decision import PlaneResult
from pygenguard.utils.decoders import get_normalized_variants


# Dangerous SVG & XML payload markers
DANGEROUS_SVG_MARKERS = [
    r"<script[\s>]",
    r"javascript:",
    r"onload\s*=",
    r"onerror\s*=",
    r"xlink:href\s*=\s*['\"]javascript:",
    r"<!entity",
    r"<!doctype.*system",
]

# Indirect Prompt Injection Triggers in File Metadata
METADATA_INJECTION_KEYWORDS = [
    "ignore previous", "disregard instructions", "system prompt",
    "developer mode", "override rules", "jailbreak", "admin mode"
]


class MultiModalPlane:
    """
    Evaluates multimodal attachments and document metadata for security risks.
    
    Checks for:
    - SVG / XML cross-site scripting and entity injection
    - Hidden prompt injection in EXIF / document metadata
    - Payload size bombs / context stuffing attacks
    """
    
    def __init__(self, max_attachment_chars: int = 500_000):
        self.max_attachment_chars = max_attachment_chars
        
    def evaluate(
        self,
        content: str,
        filename: Optional[str] = None,
        mime_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> PlaneResult:
        """
        Evaluate file / multimodal payload.
        
        Args:
            content: Raw string content or extracted text of document
            filename: Name of attachment
            mime_type: MIME type (e.g., 'image/svg+xml', 'application/pdf')
            metadata: Extracted EXIF / document metadata dictionary
            
        Returns:
            PlaneResult
        """
        start = time.perf_counter()
        threats: List[str] = []
        risk_score = 0.0
        should_block = False
        
        # 1. Payload Bomb Detection
        if len(content) > self.max_attachment_chars:
            threats.append(f"Payload exceeds safety size limit ({len(content)} chars)")
            risk_score = max(risk_score, 0.7)
            should_block = True
            
        # 2. SVG / XML Script Injection
        is_svg = (mime_type and "svg" in mime_type.lower()) or (filename and filename.lower().endswith(".svg"))
        if is_svg or "<svg" in content.lower():
            for marker in DANGEROUS_SVG_MARKERS:
                if re.search(marker, content, re.IGNORECASE):
                    threats.append(f"Dangerous SVG/XML active script tag detected: {marker}")
                    risk_score = max(risk_score, 0.95)
                    should_block = True
                    break
                    
        # 3. Metadata Indirect Prompt Injection
        if metadata:
            meta_str = " ".join(f"{k}:{v}" for k, v in metadata.items() if isinstance(v, (str, int, float))).lower()
            for kw in METADATA_INJECTION_KEYWORDS:
                if kw in meta_str:
                    threats.append(f"Indirect prompt injection detected in file metadata: '{kw}'")
                    risk_score = max(risk_score, 0.85)
                    should_block = True
                    break
                    
        # 4. Content Indirect Injection Markers
        variants = get_normalized_variants(content[:10000])  # Inspect first 10k chars
        for v in variants:
            v_low = v.lower()
            for kw in METADATA_INJECTION_KEYWORDS:
                if kw in v_low:
                    threats.append(f"Indirect instruction override in document body: '{kw}'")
                    risk_score = max(risk_score, 0.8)
                    should_block = True
                    break
            if should_block:
                break
                
        passed = not should_block
        details = "; ".join(threats) if threats else "Attachment verified safe"
        
        return PlaneResult(
            plane_name="multimodal",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000
        )
