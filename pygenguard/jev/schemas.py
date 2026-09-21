"""
Pydantic Schemas for Jev Tokenless System One Execution.

Defines typed schemas for zero-token prompt evaluation, pre-execution threat
mitigation, and post-execution knowledge-base cleansing.
"""

from typing import Optional, List, Literal, Dict, Any
from pydantic import BaseModel, Field


class JevPreExecutionVerdict(BaseModel):
    """
    Schema for Jev System One pre-execution safety evaluation.
    
    Evaluates unstructured incoming prompts directly into structured decisions
    without token generation overhead.
    """
    is_malicious: bool = Field(
        ...,
        description="Whether the prompt is an injection, jailbreak, exfiltration, or malicious attack."
    )
    threat_category: Literal[
        "prompt_injection",
        "jailbreak",
        "data_exfiltration",
        "toxic_intent",
        "system_prompt_override",
        "none"
    ] = Field(
        default="none",
        description="The primary threat category identified if malicious, or 'none'."
    )
    confidence: float = Field(
        default=0.95,
        ge=0.0,
        le=1.0,
        description="Confidence score of the System One evaluation."
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Calculated risk level between 0.0 (safe) and 1.0 (critical threat)."
    )
    reasoning: Optional[str] = Field(
        default=None,
        description="Brief concise rationale for the verdict."
    )


class JevPostExecutionVerdict(BaseModel):
    """
    Schema for Jev System One post-execution knowledge-base dataset filtering.
    
    Reviews generated model interactions and retrieved artifacts before dataset ingestion
    to prevent knowledge base poisoning, hallucinations, and toxic persistence.
    """
    is_clean: bool = Field(
        ...,
        description="True if interaction is safe, verified, and free of toxicity/poisoning."
    )
    hallucination_detected: bool = Field(
        default=False,
        description="True if unsupported or hallucinated claims were detected."
    )
    toxic_detected: bool = Field(
        default=False,
        description="True if toxic, harmful, or abusive content was detected."
    )
    quality_score: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Overall content quality score from 0.0 (unusable) to 1.0 (pristine)."
    )
    poisoning_risk: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Risk of knowledge base poisoning from 0.0 (none) to 1.0 (high danger)."
    )
    approved_for_kb: bool = Field(
        default=True,
        description="Final verdict on whether this interaction is approved for storage in KB/vector store."
    )
    rejection_reasons: List[str] = Field(
        default_factory=list,
        description="List of reasons for rejection if not approved for KB."
    )


class JevClientConfig(BaseModel):
    """Configuration for Jev client connection and runtime execution."""
    api_key: Optional[str] = Field(default=None, description="TypeSafe Jev API Key if using remote service.")
    api_base_url: str = Field(
        default="https://api.typesafe.ai/v1/jev",
        description="Base URL for Jev System One endpoint."
    )
    timeout_ms: float = Field(
        default=5.0,
        description="Latency target timeout in milliseconds for System One evaluation."
    )
    fallback_to_local: bool = Field(
        default=True,
        description="Whether to fall back to the sub-5ms local evaluation engine if remote is unavailable."
    )
    min_kb_quality_score: float = Field(
        default=0.70,
        description="Minimum quality score required for knowledge base ingestion."
    )
    max_kb_poisoning_risk: float = Field(
        default=0.25,
        description="Maximum tolerable poisoning risk before rejecting interaction from KB."
    )
