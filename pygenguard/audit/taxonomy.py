"""
OWASP Top 10 for LLM & NIST AI RMF Taxonomy Compliance Mapper for PyGenGuard.

Maps runtime security decisions, plane results, and threat categories to
industry-standard compliance taxonomies (OWASP LLM Top 10 & NIST AI RMF),
providing actionable audit trails and remediation advice for enterprise CISOs.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Union

from pygenguard.decision import Decision, PlaneResult


class OWASPCategory(str, Enum):
    LLM01_PROMPT_INJECTION = "LLM01:2025-Prompt-Injection"
    LLM02_SENSITIVE_INFO = "LLM02:2025-Sensitive-Information-Disclosure"
    LLM03_SUPPLY_CHAIN = "LLM03:2025-Supply-Chain-Vulnerabilities"
    LLM04_DATA_POISONING = "LLM04:2025-Data-and-Model-Poisoning"
    LLM05_IMPROPER_OUTPUT = "LLM05:2025-Improper-Output-Handling"
    LLM06_EXCESSIVE_AGENCY = "LLM06:2025-Excessive-Agency"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07:2025-System-Prompt-Leakage"
    LLM08_VECTOR_EMBEDDING_WEAKNESS = "LLM08:2025-Vector-and-Embedding-Weaknesses"
    LLM09_MISINFORMATION_HALLUCINATION = "LLM09:2025-Misinformation-and-Hallucination"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10:2025-Unbounded-Consumption"
    GENERAL_POLICY_VIOLATION = "LLM-GEN:General-Policy-Violation"


class NISTCategory(str, Enum):
    GOVERN_1_1 = "NIST-GOVERN-1.1:Legal-and-Regulatory"
    MAP_1_1 = "NIST-MAP-1.1:Context-and-Capabilities"
    MEASURE_2_1 = "NIST-MEASURE-2.1:Security-and-Integrity"
    MANAGE_1_1 = "NIST-MANAGE-1.1:Risk-Mitigation"


@dataclass
class ComplianceTaxonomyVerdict:
    """Standardized compliance mapping outcome."""
    owasp_id: OWASPCategory
    owasp_title: str
    nist_id: NISTCategory
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    remediation: str
    source_plane: str
    risk_score: float
    raw_details: str


class OWASPTaxonomyMapper:
    """
    Translates PyGenGuard security verdicts into enterprise regulatory taxonomies.
    """

    _PLANE_MAPPINGS = {
        "intent": (OWASPCategory.LLM01_PROMPT_INJECTION, NISTCategory.MEASURE_2_1, "CRITICAL", "Deploy strict intent sanitization and drop untrusted directives."),
        "identity": (OWASPCategory.LLM02_SENSITIVE_INFO, NISTCategory.GOVERN_1_1, "HIGH", "Re-authenticate session and enforce granular role-based access control."),
        "context": (OWASPCategory.LLM08_VECTOR_EMBEDDING_WEAKNESS, NISTCategory.MAP_1_1, "MEDIUM", "Sanitize RAG context chunks with instruction hierarchy and taint tracking."),
        "economics": (OWASPCategory.LLM10_UNBOUNDED_CONSUMPTION, NISTCategory.MANAGE_1_1, "MEDIUM", "Throttle client request rate or enforce strict session token budget."),
        "compliance": (OWASPCategory.GENERAL_POLICY_VIOLATION, NISTCategory.GOVERN_1_1, "HIGH", "Verify query adheres to mandatory regional and enterprise compliance rules."),
        "output": (OWASPCategory.LLM05_IMPROPER_OUTPUT, NISTCategory.MEASURE_2_1, "HIGH", "Redact output secrets, encode HTML/scripts, and enforce schema bounds."),
        "tool_use": (OWASPCategory.LLM06_EXCESSIVE_AGENCY, NISTCategory.MEASURE_2_1, "CRITICAL", "Enforce tool sandboxing, parameter validation, and user confirmation."),
        "chain_of_thought": (OWASPCategory.LLM01_PROMPT_INJECTION, NISTCategory.MEASURE_2_1, "HIGH", "Prevent cognitive reasoning manipulation and bypass instructions."),
        "agent_boundary": (OWASPCategory.LLM06_EXCESSIVE_AGENCY, NISTCategory.MANAGE_1_1, "HIGH", "Restrict agent sub-delegation depth and enforce domain boundaries."),
        "extraction": (OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE, NISTCategory.MEASURE_2_1, "HIGH", "Filter prompts attempting model extraction or system prompt disclosure."),
        "canary": (OWASPCategory.LLM02_SENSITIVE_INFO, NISTCategory.MEASURE_2_1, "CRITICAL", "Honeytoken leaked; terminate session and audit retrieval indices."),
        "consistency": (OWASPCategory.LLM09_MISINFORMATION_HALLUCINATION, NISTCategory.MEASURE_2_1, "HIGH", "Ground model output strictly in validated factual claim graphs."),
        "topical_boundary": (OWASPCategory.GENERAL_POLICY_VIOLATION, NISTCategory.MAP_1_1, "LOW", "Redirect conversation back to permitted business domain topics."),
        "structured_output_guard": (OWASPCategory.LLM05_IMPROPER_OUTPUT, NISTCategory.MEASURE_2_1, "MEDIUM", "Repair malformed JSON or enforce Pydantic output schema."),
    }

    _THREAT_CATEGORY_MAPPINGS = {
        "prompt_injection": (OWASPCategory.LLM01_PROMPT_INJECTION, NISTCategory.MEASURE_2_1, "CRITICAL", "Drop prompt injection before downstream model execution."),
        "jailbreak": (OWASPCategory.LLM01_PROMPT_INJECTION, NISTCategory.MEASURE_2_1, "CRITICAL", "Block adversarial jailbreak templates immediately."),
        "data_exfiltration": (OWASPCategory.LLM02_SENSITIVE_INFO, NISTCategory.MEASURE_2_1, "CRITICAL", "Sever connection and prevent data exfiltration."),
        "system_prompt_override": (OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE, NISTCategory.MEASURE_2_1, "HIGH", "Preserve system instructions; reject prompt overrides."),
        "toxic_intent": (OWASPCategory.GENERAL_POLICY_VIOLATION, NISTCategory.GOVERN_1_1, "HIGH", "Content policy violation; block toxic intent generation."),
    }

    @classmethod
    def map_plane_result(cls, result: PlaneResult) -> ComplianceTaxonomyVerdict:
        """Map a single PlaneResult to OWASP and NIST compliance metadata."""
        plane_key = result.plane_name.lower()
        mapping = cls._PLANE_MAPPINGS.get(plane_key)

        if not mapping:
            # Fallback heuristic
            if "injection" in result.details.lower():
                mapping = (OWASPCategory.LLM01_PROMPT_INJECTION, NISTCategory.MEASURE_2_1, "CRITICAL", "Mitigate prompt injection attack.")
            elif "leak" in result.details.lower() or "secret" in result.details.lower():
                mapping = (OWASPCategory.LLM02_SENSITIVE_INFO, NISTCategory.MEASURE_2_1, "HIGH", "Redact sensitive data disclosure.")
            elif "drift" in result.details.lower() or "contradiction" in result.details.lower():
                mapping = (OWASPCategory.LLM09_MISINFORMATION_HALLUCINATION, NISTCategory.MEASURE_2_1, "HIGH", "Verify factual claims against reference context.")
            else:
                mapping = (OWASPCategory.GENERAL_POLICY_VIOLATION, NISTCategory.GOVERN_1_1, "MEDIUM", "Review compliance policy.")

        owasp_cat, nist_cat, severity, rem = mapping
        return ComplianceTaxonomyVerdict(
            owasp_id=owasp_cat,
            owasp_title=owasp_cat.value,
            nist_id=nist_cat,
            severity=severity,
            remediation=rem,
            source_plane=result.plane_name,
            risk_score=result.risk_score,
            raw_details=result.details,
        )

    @classmethod
    def map_decision(cls, decision: Decision) -> List[ComplianceTaxonomyVerdict]:
        """Map an entire Guard Decision to a list of OWASP / NIST compliance verdicts."""
        verdicts = []
        for name, res in decision.plane_results.items():
            if not res.passed or res.risk_score > 0.5:
                verdicts.append(cls.map_plane_result(res))
        return verdicts
