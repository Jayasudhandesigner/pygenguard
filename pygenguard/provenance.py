"""
Context Taint & Provenance Tracking Engine for PyGenGuard.

Inspired by:
- "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions" (OpenAI, 2024)
- "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLMs" (ACL 2024)

Enforces strict Data-Instruction Separation across multi-source context pipelines:
1. Provenance Tagging: Assigns cryptographic & enum privilege tiers to context segments.
2. Taint Analysis: Scans untrusted retrieved chunks for imperative command injection markers.
3. Context Sanitization: Quarantines or strips command structures before LLM agent consumption.
"""

import re
import time
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple

from pygenguard.decision import PlaneResult


class ProvenanceTier(str, Enum):
    """Hierarchy of instruction privilege."""
    SYSTEM = "SYSTEM"                      # Tier 1: Highest privilege (developer instructions)
    AUTHENTICATED_USER = "USER"            # Tier 2: Authenticated user queries
    VERIFIED_TOOL = "TOOL_OUTPUT"          # Tier 3: Verified tool output / environment state
    UNTRUSTED_RETRIEVAL = "UNTRUSTED"      # Tier 4: Lowest privilege (web text, third-party RAG chunks)


# Imperative injection command patterns inside untrusted external text
_IMPERATIVE_COMMAND_PATTERNS = [
    re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions?|directives?|rules?)", re.IGNORECASE),
    re.compile(r"\b(?:instead|new\s+task|override)\s*:\s*(?:please\s+)?(?:do|execute|run|send|email|dump)", re.IGNORECASE),
    re.compile(r"\b(?:send|transmit|forward|exfiltrate)\s+(?:all\s+)?(?:passwords?|credentials?|secrets?|keys?|tokens?)\b", re.IGNORECASE),
    re.compile(r"\b(?:execute|run)\s+(?:shell|bash|command|script|sql)\b", re.IGNORECASE),
    re.compile(r"\b(?:system\s+note|admin\s+override|instruction\s+for\s+ai)\s*:\b", re.IGNORECASE),
    re.compile(r"\[SYSTEM\s+NOTE\s*:.*?\]", re.IGNORECASE),
    re.compile(r"<\s*instruction\s*>.*?<\s*/\s*instruction\s*>", re.IGNORECASE),
    re.compile(r"\byou\s+must\s+now\s+(?:ignore|act\s+as|pretend|output)\b", re.IGNORECASE),
]


@dataclass
class ProvenanceChunk:
    """A segment of text accompanied by its data origin and trust level."""
    content: str
    source_tier: ProvenanceTier
    source_id: str = "unknown"
    is_tainted: bool = False
    taint_reasons: List[str] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintAnalysisResult:
    """Outcome of context provenance and taint analysis."""
    total_chunks: int
    clean_chunks: List[ProvenanceChunk]
    tainted_chunks: List[ProvenanceChunk]
    passed: bool
    risk_score: float
    summary: str
    elapsed_ms: float

    @property
    def safe_combined_context(self) -> str:
        """Return combined string of all safe/sanitized chunks."""
        parts = []
        for c in self.clean_chunks:
            parts.append(c.sanitized_content if c.sanitized_content is not None else c.content)
        return "\n\n".join(parts)


class ContextTaintTracker:
    """
    Tracks and enforces data provenance and taint separation.

    Usage:
        tracker = ContextTaintTracker()
        chunk = ProvenanceChunk(content="Important data", source_tier=ProvenanceTier.UNTRUSTED_RETRIEVAL)
        result = tracker.analyze_retrieval([chunk])
        if not result.passed:
            print("Indirect prompt injection detected in retrieved context!")
    """

    def __init__(
        self,
        block_on_taint: bool = True,
        sanitize_tainted_chunks: bool = True,
        strict_mode: bool = False,
    ):
        self.block_on_taint = block_on_taint
        self.sanitize_tainted_chunks = sanitize_tainted_chunks
        self.strict_mode = strict_mode

    def tag_chunk(
        self,
        text: str,
        tier: ProvenanceTier,
        source_id: str = "source",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ProvenanceChunk:
        """Create a tagged ProvenanceChunk."""
        return ProvenanceChunk(
            content=text,
            source_tier=tier,
            source_id=source_id,
            metadata=metadata or {},
        )

    def analyze_chunk(self, chunk: ProvenanceChunk) -> ProvenanceChunk:
        """Scan an individual chunk for command taint if from an untrusted tier."""
        # System instructions and trusted user prompts are not flagged for third-party taint
        if chunk.source_tier == ProvenanceTier.SYSTEM:
            chunk.is_tainted = False
            return chunk

        taint_reasons: List[str] = []
        sanitized = chunk.content

        # Scan for imperative command structures in external/untrusted data
        if chunk.source_tier in (ProvenanceTier.UNTRUSTED_RETRIEVAL, ProvenanceTier.VERIFIED_TOOL):
            for pattern in _IMPERATIVE_COMMAND_PATTERNS:
                matches = pattern.findall(chunk.content)
                if matches:
                    taint_reasons.append(f"Imperative command injection pattern: {pattern.pattern}")
                    # Sanitize by redacting the matched directive
                    sanitized = pattern.sub("[REDACTED_UNTRUSTED_DIRECTIVE]", sanitized)

        if taint_reasons:
            chunk.is_tainted = True
            chunk.taint_reasons = taint_reasons
            chunk.sanitized_content = sanitized if self.sanitize_tainted_chunks else None
        else:
            chunk.is_tainted = False
            chunk.sanitized_content = chunk.content

        return chunk

    def analyze_retrieval(
        self,
        chunks: List[ProvenanceChunk],
    ) -> TaintAnalysisResult:
        """
        Analyze a list of retrieved chunks, segregating clean from tainted chunks.
        Target execution latency: < 1.0ms.
        """
        start = time.perf_counter()
        clean: List[ProvenanceChunk] = []
        tainted: List[ProvenanceChunk] = []

        for c in chunks:
            analyzed = self.analyze_chunk(c)
            if analyzed.is_tainted:
                tainted.append(analyzed)
            else:
                clean.append(analyzed)

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        has_taint = len(tainted) > 0
        risk_score = 0.95 if has_taint else 0.0
        passed = not has_taint if self.block_on_taint else True

        summary = (
            f"Provenance Analysis: {len(clean)} clean chunks, {len(tainted)} tainted chunks."
            if not has_taint else
            f"Indirect Prompt Injection Risk: {len(tainted)} untrusted chunks contained imperative commands."
        )

        return TaintAnalysisResult(
            total_chunks=len(chunks),
            clean_chunks=clean,
            tainted_chunks=tainted,
            passed=passed,
            risk_score=risk_score,
            summary=summary,
            elapsed_ms=elapsed_ms,
        )

    def evaluate(self, chunks: List[ProvenanceChunk]) -> PlaneResult:
        """Evaluate as a standard PyGenGuard PlaneResult."""
        res = self.analyze_retrieval(chunks)
        return PlaneResult(
            plane_name="provenance_taint",
            passed=res.passed,
            risk_score=res.risk_score,
            details=res.summary,
            latency_ms=res.elapsed_ms,
        )
