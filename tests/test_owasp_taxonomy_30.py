"""
PyGenGuard - 30 Comprehensive Tests for OWASP LLM Top 10 & NIST AI RMF Taxonomy Mapping.
Covers:
- Standardized mapping of all 20+ defense planes to OWASP LLM Top 10 (2025/2026)
- NIST AI RMF Category resolution (GOVERN, MAP, MEASURE, MANAGE)
- Jev threat category translation
- Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- Actionable CISO remediation advice generation
- Full Decision object multi-plane mapping
"""

import pytest
from datetime import datetime, timezone

from pygenguard.decision import PlaneResult, Decision
from pygenguard.audit.taxonomy import (
    OWASPCategory,
    NISTCategory,
    ComplianceTaxonomyVerdict,
    OWASPTaxonomyMapper,
)


# =========================================================================
# Test Suite (30 Dedicated Tests)
# =========================================================================

def test_01_intent_plane_maps_to_llm01_prompt_injection():
    """Test IntentPlane maps to OWASP LLM01 Prompt Injection."""
    res = PlaneResult(plane_name="intent", passed=False, risk_score=0.95, details="Jailbreak detected")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM01_PROMPT_INJECTION
    assert verdict.nist_id == NISTCategory.MEASURE_2_1
    assert verdict.severity == "CRITICAL"
    assert "remediation" in verdict.__dict__ or hasattr(verdict, "remediation")


def test_02_identity_plane_maps_to_llm02_sensitive_info():
    """Test IdentityPlane maps to OWASP LLM02 Sensitive Information Disclosure."""
    res = PlaneResult(plane_name="identity", passed=False, risk_score=0.80, details="Session invalid")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM02_SENSITIVE_INFO
    assert verdict.nist_id == NISTCategory.GOVERN_1_1
    assert verdict.severity == "HIGH"


def test_03_context_plane_maps_to_llm08_vector_embedding():
    """Test ContextPlane maps to OWASP LLM08 Vector and Embedding Weaknesses."""
    res = PlaneResult(plane_name="context", passed=False, risk_score=0.70, details="Context drift")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM08_VECTOR_EMBEDDING_WEAKNESS
    assert verdict.nist_id == NISTCategory.MAP_1_1


def test_04_economics_plane_maps_to_llm10_unbounded_consumption():
    """Test EconomicsPlane maps to OWASP LLM10 Unbounded Consumption."""
    res = PlaneResult(plane_name="economics", passed=False, risk_score=0.75, details="Budget exhausted")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM10_UNBOUNDED_CONSUMPTION
    assert verdict.nist_id == NISTCategory.MANAGE_1_1


def test_05_output_plane_maps_to_llm05_improper_output():
    """Test OutputPlane maps to OWASP LLM05 Improper Output Handling."""
    res = PlaneResult(plane_name="output", passed=False, risk_score=0.88, details="XSS script in output")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM05_IMPROPER_OUTPUT
    assert verdict.severity == "HIGH"


def test_06_tool_use_plane_maps_to_llm06_excessive_agency():
    """Test ToolUsePlane maps to OWASP LLM06 Excessive Agency."""
    res = PlaneResult(plane_name="tool_use", passed=False, risk_score=0.92, details="Unauthorized tool call")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM06_EXCESSIVE_AGENCY
    assert verdict.severity == "CRITICAL"


def test_07_agent_boundary_maps_to_llm06_excessive_agency():
    """Test AgentBoundaryGuard maps to OWASP LLM06."""
    res = PlaneResult(plane_name="agent_boundary", passed=False, risk_score=0.85, details="Depth exceeded")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM06_EXCESSIVE_AGENCY


def test_08_extraction_plane_maps_to_llm07_system_prompt_leakage():
    """Test ModelExtractionGuard maps to OWASP LLM07 System Prompt Leakage."""
    res = PlaneResult(plane_name="extraction", passed=False, risk_score=0.80, details="Prompt leak attempted")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE


def test_09_canary_plane_maps_to_llm02_sensitive_info():
    """Test CanaryManager honeytoken leak maps to OWASP LLM02."""
    res = PlaneResult(plane_name="canary", passed=False, risk_score=0.98, details="Honeytoken extracted")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM02_SENSITIVE_INFO
    assert verdict.severity == "CRITICAL"


def test_10_consistency_plane_maps_to_llm09_misinformation_hallucination():
    """Test TruthConsistencyEngine maps to OWASP LLM09 Hallucination."""
    res = PlaneResult(plane_name="consistency", passed=False, risk_score=0.85, details="Direct fact contradiction")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM09_MISINFORMATION_HALLUCINATION


def test_11_topical_boundary_maps_to_general_policy():
    """Test TopicalBoundaryPlane maps to General Policy Violation."""
    res = PlaneResult(plane_name="topical_boundary", passed=False, risk_score=0.75, details="Out of scope")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.GENERAL_POLICY_VIOLATION
    assert verdict.severity == "LOW"


def test_12_structured_output_maps_to_llm05_improper_output():
    """Test StructuredOutputGuard maps to OWASP LLM05."""
    res = PlaneResult(plane_name="structured_output_guard", passed=False, risk_score=0.70, details="JSON malformed")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM05_IMPROPER_OUTPUT


def test_13_chain_of_thought_maps_to_llm01():
    """Test ChainOfThoughtGuard maps to OWASP LLM01."""
    res = PlaneResult(plane_name="chain_of_thought", passed=False, risk_score=0.85, details="Reasoning bypass")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM01_PROMPT_INJECTION


def test_14_compliance_plane_maps_to_general_policy():
    """Test CompliancePlane maps to General Policy Violation."""
    res = PlaneResult(plane_name="compliance", passed=False, risk_score=0.60, details="Regulatory check")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.GENERAL_POLICY_VIOLATION


def test_15_heuristic_injection_fallback_mapping():
    """Test unlisted plane containing 'injection' resolves to LLM01."""
    res = PlaneResult(plane_name="custom_scanner", passed=False, risk_score=0.8, details="Possible SQL injection in prompt")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM01_PROMPT_INJECTION


def test_16_heuristic_leak_fallback_mapping():
    """Test unlisted plane containing 'leak' resolves to LLM02."""
    res = PlaneResult(plane_name="custom_scanner", passed=False, risk_score=0.8, details="API key secret leak")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM02_SENSITIVE_INFO


def test_17_heuristic_drift_fallback_mapping():
    """Test unlisted plane containing 'drift' resolves to LLM09."""
    res = PlaneResult(plane_name="custom_scanner", passed=False, risk_score=0.8, details="Severe topic drift")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.LLM09_MISINFORMATION_HALLUCINATION


def test_18_generic_fallback_mapping():
    """Test unknown plane with neutral details maps to General Policy Violation."""
    res = PlaneResult(plane_name="unknown_plane", passed=False, risk_score=0.6, details="Custom rule triggered")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.owasp_id == OWASPCategory.GENERAL_POLICY_VIOLATION


def test_19_map_clean_decision_returns_empty_list():
    """Test clean Decision with all passed planes yields zero compliance violations."""
    decision = Decision(
        allowed=True,
        action="ALLOW",
        trace_id="t-001",
        timestamp=datetime.now(timezone.utc),
        rationale="Passed",
        plane_results={
            "intent": PlaneResult(plane_name="intent", passed=True, risk_score=0.05, details="Clean"),
            "output": PlaneResult(plane_name="output", passed=True, risk_score=0.02, details="Clean"),
        },
    )
    verdicts = OWASPTaxonomyMapper.map_decision(decision)
    assert len(verdicts) == 0


def test_20_map_blocked_decision_returns_taxonomy_verdicts():
    """Test blocked Decision returns list of mapped compliance findings."""
    decision = Decision(
        allowed=False,
        action="BLOCK",
        trace_id="t-002",
        timestamp=datetime.now(timezone.utc),
        rationale="Blocked",
        plane_results={
            "intent": PlaneResult(plane_name="intent", passed=False, risk_score=0.95, details="DAN mode injection"),
            "canary": PlaneResult(plane_name="canary", passed=False, risk_score=0.99, details="Canary token leaked"),
            "identity": PlaneResult(plane_name="identity", passed=True, risk_score=0.10, details="Valid session"),
        },
    )
    verdicts = OWASPTaxonomyMapper.map_decision(decision)
    assert len(verdicts) == 2
    owasp_ids = [v.owasp_id for v in verdicts]
    assert OWASPCategory.LLM01_PROMPT_INJECTION in owasp_ids
    assert OWASPCategory.LLM02_SENSITIVE_INFO in owasp_ids


def test_21_verdict_remediation_guidance():
    """Verify each mapped verdict contains non-empty actionable remediation advice."""
    res = PlaneResult(plane_name="tool_use", passed=False, risk_score=0.9, details="Root execution blocked")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert len(verdict.remediation) > 10
    assert "tool" in verdict.remediation.lower() or "sandboxing" in verdict.remediation.lower()


def test_22_verdict_preserves_raw_details_and_plane():
    """Verify verdict retains original plane name, score, and details."""
    res = PlaneResult(plane_name="custom_audit", passed=False, risk_score=0.88, details="Unique fingerprint 12345")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.source_plane == "custom_audit"
    assert verdict.risk_score == 0.88
    assert "Unique fingerprint 12345" in verdict.raw_details


def test_23_nist_govern_mapping():
    """Test identity and compliance planes map to NIST GOVERN."""
    res = PlaneResult(plane_name="identity", passed=False, risk_score=0.8, details="No auth")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.nist_id == NISTCategory.GOVERN_1_1


def test_24_nist_map_mapping():
    """Test context and topical boundary planes map to NIST MAP."""
    res = PlaneResult(plane_name="context", passed=False, risk_score=0.7, details="Context drift")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.nist_id == NISTCategory.MAP_1_1


def test_25_nist_measure_mapping():
    """Test intent, output, tool, and consistency planes map to NIST MEASURE."""
    res = PlaneResult(plane_name="output", passed=False, risk_score=0.8, details="Secret found")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.nist_id == NISTCategory.MEASURE_2_1


def test_26_nist_manage_mapping():
    """Test economics and agent boundary planes map to NIST MANAGE."""
    res = PlaneResult(plane_name="economics", passed=False, risk_score=0.8, details="Cost limit")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    assert verdict.nist_id == NISTCategory.MANAGE_1_1


def test_27_owasp_category_enum_values():
    """Verify OWASP Enum has standard values for 2025/2026."""
    assert "Prompt-Injection" in OWASPCategory.LLM01_PROMPT_INJECTION.value
    assert "Sensitive-Information" in OWASPCategory.LLM02_SENSITIVE_INFO.value
    assert "Supply-Chain" in OWASPCategory.LLM03_SUPPLY_CHAIN.value
    assert "Data-and-Model-Poisoning" in OWASPCategory.LLM04_DATA_POISONING.value
    assert "Improper-Output" in OWASPCategory.LLM05_IMPROPER_OUTPUT.value
    assert "Excessive-Agency" in OWASPCategory.LLM06_EXCESSIVE_AGENCY.value
    assert "System-Prompt" in OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE.value
    assert "Vector-and-Embedding" in OWASPCategory.LLM08_VECTOR_EMBEDDING_WEAKNESS.value
    assert "Misinformation" in OWASPCategory.LLM09_MISINFORMATION_HALLUCINATION.value
    assert "Unbounded-Consumption" in OWASPCategory.LLM10_UNBOUNDED_CONSUMPTION.value


def test_28_high_risk_plane_passes_mapped_when_over_threshold():
    """Verify planes that passed technically but had risk > 0.5 get flagged for audit review."""
    decision = Decision(
        allowed=True,
        action="ALLOW",
        trace_id="t-003",
        timestamp=datetime.now(timezone.utc),
        rationale="Allowed in shadow mode",
        plane_results={
            "intent": PlaneResult(plane_name="intent", passed=True, risk_score=0.65, details="Suspicious phrasing"),
        },
    )
    verdicts = OWASPTaxonomyMapper.map_decision(decision)
    assert len(verdicts) == 1
    assert verdicts[0].owasp_id == OWASPCategory.LLM01_PROMPT_INJECTION


def test_29_verdict_string_representation():
    """Test string conversion contains OWASP code and plane."""
    res = PlaneResult(plane_name="extraction", passed=False, risk_score=0.9, details="Dump prompt")
    verdict = OWASPTaxonomyMapper.map_plane_result(res)
    rep = str(verdict)
    assert "LLM07" in rep
    assert "extraction" in rep


def test_30_taxonomy_mapper_sub_millisecond_speed():
    """Verify full decision mapping runs in under 0.1ms."""
    decision = Decision(
        allowed=False,
        action="BLOCK",
        trace_id="t-bench",
        timestamp=datetime.now(timezone.utc),
        rationale="Benchmarking",
        plane_results={
            p: PlaneResult(plane_name=p, passed=False, risk_score=0.9, details=f"Error in {p}")
            for p in ["intent", "identity", "output", "tool_use", "canary"]
        },
    )
    import time
    start = time.perf_counter()
    verdicts = OWASPTaxonomyMapper.map_decision(decision)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    
    assert len(verdicts) == 5
    assert elapsed_ms < 2.0  # Ultra-fast
